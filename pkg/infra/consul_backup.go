package infra

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/keyzon-technologies/mpcinfra/pkg/encryption"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
)

const (
	consulBackupMagic      = "mpcinfra_CONSUL"
	defaultConsulBackupDir = "./backups"
)

// ConsulBackupUploader is the same interface as kvstore.BackupUploader — allows reuse of R2Uploader.
type ConsulBackupUploader interface {
	Upload(ctx context.Context, filename string, data []byte) error
	ListObjects(ctx context.Context) ([]string, error)
	DeleteObject(ctx context.Context, key string) error
}

type ConsulBackupMeta struct {
	Algo            string `json:"algo"`
	NonceB64        string `json:"nonce_b64"`
	CreatedAt       string `json:"created_at"`
	EncryptionKeyID string `json:"encryption_key_id"`
}

type consulBackupExecutor struct {
	nodeID         string
	kv             ConsulKV
	encKey         []byte
	backupDir      string
	uploader       ConsulBackupUploader
	retentionCount int
	lastHash       [32]byte // SHA-256 of last serialized KV payload
}

const defaultRetentionCount = 3

// NewConsulBackupExecutor creates a backup executor for the Consul KV store.
// It exports all keys under every managed prefix, encrypts with AES-256-GCM,
// writes locally, and optionally uploads to remote storage (e.g. R2).
// retentionCount controls how many remote backups to keep (0 = keep all).
func NewConsulBackupExecutor(
	nodeID string,
	kv ConsulKV,
	encryptionKey []byte,
	backupDir string,
	retentionCount int,
	uploader ...ConsulBackupUploader,
) *consulBackupExecutor {
	if backupDir == "" {
		backupDir = defaultConsulBackupDir
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		panic(fmt.Errorf("consul backup: failed to create backup directory: %w", err))
	}
	if retentionCount <= 0 {
		retentionCount = defaultRetentionCount
	}
	exe := &consulBackupExecutor{
		nodeID:         nodeID,
		kv:             kv,
		encKey:         encryptionKey,
		backupDir:      backupDir,
		retentionCount: retentionCount,
	}
	if len(uploader) > 0 {
		exe.uploader = uploader[0]
	}
	return exe
}

// Execute exports all Consul KV pairs, encrypts and saves them locally,
// then uploads to remote storage if an uploader is configured.
func (c *consulBackupExecutor) Execute() error {
	pairs, _, err := c.kv.List("", nil)
	if err != nil {
		return fmt.Errorf("consul backup: failed to list KV pairs: %w", err)
	}
	if len(pairs) == 0 {
		logger.Info("Consul backup: no keys found, skipping")
		return nil
	}

	// Serialize all KV pairs to JSON
	plain, err := json.Marshal(pairs)
	if err != nil {
		return fmt.Errorf("consul backup: failed to marshal KV pairs: %w", err)
	}

	// Skip backup if data hasn't changed since last run
	currentHash := sha256.Sum256(plain)
	if currentHash == c.lastHash {
		logger.Info("Consul backup: no changes detected, skipping")
		return nil
	}

	// Encrypt
	ct, nonce, err := encryption.EncryptAESGCM(plain, c.encKey)
	if err != nil {
		return fmt.Errorf("consul backup: encryption failed: %w", err)
	}

	now := time.Now()
	filename := fmt.Sprintf("consul-backup-%s-%s.enc", c.nodeID, now.Format("2006-01-02_15-04-05"))
	outPath := filepath.Join(c.backupDir, filename)

	meta := ConsulBackupMeta{
		Algo:            "AES-256-GCM",
		NonceB64:        base64.StdEncoding.EncodeToString(nonce),
		CreatedAt:       now.Format(time.RFC3339),
		EncryptionKeyID: fmt.Sprintf("%x", sha256.Sum256(c.encKey))[:16],
	}
	metaJSON, _ := json.Marshal(meta)

	metaLen := len(metaJSON)
	if metaLen > math.MaxUint32 {
		return fmt.Errorf("consul backup: metaJSON too large")
	}

	var fileBuf bytes.Buffer
	fileBuf.Write([]byte(consulBackupMagic))
	if err := binary.Write(&fileBuf, binary.BigEndian, uint32(metaLen)); err != nil {
		return err
	}
	fileBuf.Write(metaJSON)
	fileBuf.Write(ct)

	fileBytes := fileBuf.Bytes()

	if err := os.WriteFile(outPath, fileBytes, 0600); err != nil {
		return fmt.Errorf("consul backup: failed to write file: %w", err)
	}
	c.lastHash = currentHash
	logger.Info("Consul backup written", "file", filename, "keys", len(pairs))

	if c.uploader != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		if uploadErr := c.uploader.Upload(ctx, filename, fileBytes); uploadErr != nil {
			logger.Error("Consul backup: remote upload failed", uploadErr, "file", filename)
		} else {
			logger.Info("Consul backup: remote upload successful", "file", filename)
			c.pruneRemoteBackups(ctx)
		}
	}

	return nil
}

// pruneRemoteBackups deletes old remote backups, keeping only the most recent retentionCount files.
func (c *consulBackupExecutor) pruneRemoteBackups(ctx context.Context) {
	keys, err := c.uploader.ListObjects(ctx)
	if err != nil {
		logger.Error("Consul backup: failed to list remote backups for pruning", err)
		return
	}

	// Filter only this node's backup files
	prefix := fmt.Sprintf("consul-backup-%s-", c.nodeID)
	var nodeKeys []string
	for _, k := range keys {
		if len(k) > len(prefix) {
			// match by suffix of the key (strip any path prefix)
			base := filepath.Base(k)
			if len(base) > len(prefix) && base[:len(prefix)] == prefix {
				nodeKeys = append(nodeKeys, k)
			}
		}
	}

	// Keys are sorted ascending by ListObjects — oldest first
	if len(nodeKeys) <= c.retentionCount {
		return
	}

	toDelete := nodeKeys[:len(nodeKeys)-c.retentionCount]
	for _, key := range toDelete {
		if err := c.uploader.DeleteObject(ctx, key); err != nil {
			logger.Error("Consul backup: failed to delete old backup", err, "key", key)
		} else {
			logger.Info("Consul backup: deleted old backup", "key", key)
		}
	}
}

// StartPeriodicConsulBackup runs Execute on a ticker and returns a stop function.
func StartPeriodicConsulBackup(ctx context.Context, exe *consulBackupExecutor, periodSeconds int) func() {
	if periodSeconds <= 0 {
		periodSeconds = 300
	}
	ticker := time.NewTicker(time.Duration(periodSeconds) * time.Second)
	backupCtx, cancel := context.WithCancel(ctx)
	go func() {
		for {
			select {
			case <-backupCtx.Done():
				ticker.Stop()
				logger.Info("Consul backup job stopped")
				return
			case <-ticker.C:
				logger.Info("Running periodic Consul KV backup...")
				if err := exe.Execute(); err != nil {
					logger.Error("Consul backup failed", err)
				}
			}
		}
	}()
	return cancel
}

// RestoreConsulBackup reads an encrypted backup file and restores all KV pairs into Consul.
func RestoreConsulBackup(path string, kv ConsulKV, encryptionKey []byte) error {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("consul restore: failed to read file: %w", err)
	}
	return RestoreConsulBackupFromBytes(fileBytes, kv, encryptionKey)
}

// RestoreConsulBackupFromBytes restores all KV pairs into Consul from an in-memory backup.
func RestoreConsulBackupFromBytes(fileBytes []byte, kv ConsulKV, encryptionKey []byte) error {
	magicLen := len(consulBackupMagic)
	if len(fileBytes) < magicLen+4 {
		return fmt.Errorf("consul restore: file too short")
	}
	if string(fileBytes[:magicLen]) != consulBackupMagic {
		return fmt.Errorf("consul restore: invalid magic header")
	}

	offset := magicLen
	metaLen := binary.BigEndian.Uint32(fileBytes[offset : offset+4])
	offset += 4

	if int(offset)+int(metaLen) > len(fileBytes) {
		return fmt.Errorf("consul restore: metadata truncated")
	}

	var meta ConsulBackupMeta
	if err := json.Unmarshal(fileBytes[offset:offset+int(metaLen)], &meta); err != nil {
		return fmt.Errorf("consul restore: failed to parse metadata: %w", err)
	}
	offset += int(metaLen)

	ct := fileBytes[offset:]
	nonce, err := base64.StdEncoding.DecodeString(meta.NonceB64)
	if err != nil {
		return fmt.Errorf("consul restore: invalid nonce: %w", err)
	}

	plain, err := encryption.DecryptAESGCM(ct, encryptionKey, nonce)
	if err != nil {
		return fmt.Errorf("consul restore: decryption failed: %w", err)
	}

	var pairs api.KVPairs
	if err := json.Unmarshal(plain, &pairs); err != nil {
		return fmt.Errorf("consul restore: failed to unmarshal KV pairs: %w", err)
	}

	for _, pair := range pairs {
		if _, err := kv.Put(&api.KVPair{Key: pair.Key, Value: pair.Value}, nil); err != nil {
			return fmt.Errorf("consul restore: failed to put key %q: %w", pair.Key, err)
		}
	}

	logger.Info("Consul restore complete", "keys", len(pairs))
	return nil
}
