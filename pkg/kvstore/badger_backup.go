package kvstore

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

	"github.com/dgraph-io/badger/v4"
	"github.com/keyzon-technologies/mpcinfra/pkg/encryption"
	"github.com/rs/zerolog/log"
)

// BackupUploader is an optional interface for pushing encrypted backup files to remote storage.
type BackupUploader interface {
	Upload(ctx context.Context, filename string, data []byte) error
}

const (
	magic            = "mpcinfra_BACKUP"
	defaultBackupDir = "./backups"
)

type BadgerBackupMeta struct {
	Algo            string `json:"algo"`
	NonceB64        string `json:"nonce_b64"`
	CreatedAt       string `json:"created_at"`
	EncryptionKeyID string `json:"encryption_key_id"`
}

type badgerBackupExecutor struct {
	NodeID              string
	DB                  *badger.DB
	BackupEncryptionKey []byte
	BackupDir           string
	Uploader            BackupUploader
	lastHash            [32]byte // SHA-256 of last backup payload
}

// NewBadgerBackupExecutor creates a new backup executor.
func NewBadgerBackupExecutor(
	nodeID string,
	db *badger.DB,
	backupEncryptionKey []byte,
	backupDir string,
	uploader ...BackupUploader,
) *badgerBackupExecutor {
	if backupDir == "" {
		backupDir = defaultBackupDir
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		panic(fmt.Errorf("failed to create backup directory: %w", err))
	}
	exe := &badgerBackupExecutor{
		NodeID:              nodeID,
		DB:                  db,
		BackupEncryptionKey: backupEncryptionKey,
		BackupDir:           backupDir,
	}
	if len(uploader) > 0 {
		exe.Uploader = uploader[0]
	}
	return exe
}

// latestFilename returns the fixed filename used for the full backup.
func (b *badgerBackupExecutor) latestFilename() string {
	return fmt.Sprintf("backup-%s-latest.enc", b.NodeID)
}

// Execute performs a full backup (since=0), always overwriting the same file.
// The result is always self-contained and can be restored independently.
func (b *badgerBackupExecutor) Execute() error {
	var plain bytes.Buffer
	if _, err := b.DB.Backup(&plain, 0); err != nil {
		return err
	}
	if plain.Len() == 0 {
		log.Info().Msg("[SKIP] Database is empty, skipping backup.")
		return nil
	}

	// Skip if data hasn't changed since last backup
	currentHash := sha256.Sum256(plain.Bytes())
	if currentHash == b.lastHash {
		log.Info().Msg("[SKIP] No changes detected, skipping backup.")
		return nil
	}

	ct, nonce, err := encryption.EncryptAESGCM(plain.Bytes(), b.BackupEncryptionKey)
	if err != nil {
		return err
	}

	now := time.Now()
	meta := BadgerBackupMeta{
		Algo:            "AES-256-GCM",
		NonceB64:        base64.StdEncoding.EncodeToString(nonce),
		CreatedAt:       now.Format(time.RFC3339),
		EncryptionKeyID: fmt.Sprintf("%x", sha256.Sum256(b.BackupEncryptionKey))[:16],
	}
	metaJSON, _ := json.Marshal(meta)

	metaLen := len(metaJSON)
	if metaLen > math.MaxUint32 {
		return fmt.Errorf("metaJSON too large")
	}

	var fileBuf bytes.Buffer
	fileBuf.Write([]byte(magic))
	if err := binary.Write(&fileBuf, binary.BigEndian, uint32(metaLen)); err != nil {
		return err
	}
	fileBuf.Write(metaJSON)
	fileBuf.Write(ct)
	fileBytes := fileBuf.Bytes()

	filename := b.latestFilename()
	outPath := filepath.Join(b.BackupDir, filename)

	if err := os.WriteFile(outPath, fileBytes, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}
	b.lastHash = currentHash
	log.Info().Str("file", filename).Int("bytes", len(fileBytes)).Msg("Backup written successfully")

	if b.Uploader != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if uploadErr := b.Uploader.Upload(ctx, filename, fileBytes); uploadErr != nil {
			log.Error().Err(uploadErr).Str("file", filename).Msg("Remote backup upload failed")
		} else {
			log.Info().Str("file", filename).Msg("Remote backup uploaded successfully")
		}
	}

	return nil
}

// RestoreBackup opens the latest backup file and loads it into a new Badger database at restorePath.
func (b *badgerBackupExecutor) RestoreBackup(restorePath string, encryptionKey []byte) error {
	if err := os.MkdirAll(restorePath, 0700); err != nil {
		return fmt.Errorf("failed to create restore directory: %w", err)
	}

	backupPath := filepath.Join(b.BackupDir, b.latestFilename())
	plain, err := b.decryptFile(backupPath)
	if err != nil {
		return err
	}

	opts := badger.DefaultOptions(restorePath).
		WithEncryptionKey(encryptionKey).
		WithIndexCacheSize(10 << 20).
		WithLogger(newQuietBadgerLogger())

	restoreDB, err := badger.Open(opts)
	if err != nil {
		return err
	}

	if err := restoreDB.Load(bytes.NewReader(plain), 10); err != nil {
		if closeErr := restoreDB.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("failed to close restore database after load error")
		}
		return fmt.Errorf("failed to load backup data: %w", err)
	}

	if err := restoreDB.Close(); err != nil {
		return fmt.Errorf("failed to close restore database: %w", err)
	}

	fmt.Println("✅ Restore complete:", restorePath)
	return nil
}

// RestoreBackupFromBytes loads a backup from in-memory bytes into a new Badger database at restorePath.
func (b *badgerBackupExecutor) RestoreBackupFromBytes(restorePath string, fileBytes []byte, encryptionKey []byte) error {
	if err := os.MkdirAll(restorePath, 0700); err != nil {
		return fmt.Errorf("failed to create restore directory: %w", err)
	}

	plain, err := decryptBackupBytes(fileBytes, b.BackupEncryptionKey)
	if err != nil {
		return err
	}

	opts := badger.DefaultOptions(restorePath).
		WithEncryptionKey(encryptionKey).
		WithIndexCacheSize(10 << 20).
		WithLogger(newQuietBadgerLogger())

	restoreDB, err := badger.Open(opts)
	if err != nil {
		return err
	}

	if err := restoreDB.Load(bytes.NewReader(plain), 10); err != nil {
		if closeErr := restoreDB.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("failed to close restore database after load error")
		}
		return fmt.Errorf("failed to load backup data: %w", err)
	}

	if err := restoreDB.Close(); err != nil {
		return fmt.Errorf("failed to close restore database: %w", err)
	}

	fmt.Println("✅ Restore complete:", restorePath)
	return nil
}

func (b *badgerBackupExecutor) decryptFile(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	fileBytes, err := os.ReadFile(cleanPath) // #nosec G304 -- path is constructed internally via filepath.Join
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file %s: %w", cleanPath, err)
	}
	return decryptBackupBytes(fileBytes, b.BackupEncryptionKey)
}

func decryptBackupBytes(fileBytes []byte, key []byte) ([]byte, error) {
	magicLen := len(magic)
	if len(fileBytes) < magicLen+4 {
		return nil, fmt.Errorf("backup file too short")
	}
	if string(fileBytes[:magicLen]) != magic {
		return nil, fmt.Errorf("invalid backup magic header")
	}

	offset := magicLen
	metaLen := binary.BigEndian.Uint32(fileBytes[offset : offset+4])
	offset += 4

	if int(offset)+int(metaLen) > len(fileBytes) {
		return nil, fmt.Errorf("backup metadata truncated")
	}

	var meta BadgerBackupMeta
	if err := json.Unmarshal(fileBytes[offset:offset+int(metaLen)], &meta); err != nil {
		return nil, fmt.Errorf("failed to parse backup metadata: %w", err)
	}
	offset += int(metaLen)

	nonce, err := base64.StdEncoding.DecodeString(meta.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce in backup metadata: %w", err)
	}

	ct := fileBytes[offset:]
	plain, err := encryption.DecryptAESGCM(ct, key, nonce)
	if err != nil {
		return nil, fmt.Errorf("backup decryption failed: %w", err)
	}

	return plain, nil
}
