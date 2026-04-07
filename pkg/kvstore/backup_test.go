package kvstore

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateRandomKey(size int) []byte {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func generateTestKeys() ([]byte, []byte) {
	return generateRandomKey(32), generateRandomKey(32)
}

func openTestDB(t *testing.T, path string, encKey []byte) *badger.DB {
	t.Helper()
	opts := badger.DefaultOptions(path).
		WithEncryptionKey(encKey).
		WithIndexCacheSize(10 << 20).
		WithSyncWrites(false).
		WithLogger(newQuietBadgerLogger())
	db, err := badger.Open(opts)
	require.NoError(t, err)
	return db
}

// ── Execute ────────────────────────────────────────────────────────────────────

func TestBadgerBackupExecutor_Execute(t *testing.T) {
	testDir := t.TempDir()
	encKey, backupKey := generateTestKeys()
	db := openTestDB(t, filepath.Join(testDir, "db"), encKey)
	defer db.Close()

	backupDir := filepath.Join(testDir, "backups")
	executor := NewBadgerBackupExecutor("node0", db, backupKey, backupDir)

	latestFile := filepath.Join(backupDir, "backup-node0-latest.enc")

	t.Run("creates latest file on first backup", func(t *testing.T) {
		require.NoError(t, db.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte("k1"), []byte("v1"))
		}))

		require.NoError(t, executor.Execute())

		_, err := os.Stat(latestFile)
		require.NoError(t, err, "backup-node0-latest.enc should exist")
	})

	t.Run("overwrites same file on second backup", func(t *testing.T) {
		info1, err := os.Stat(latestFile)
		require.NoError(t, err)
		size1 := info1.Size()

		require.NoError(t, db.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte("k2"), []byte("v2"))
		}))

		require.NoError(t, executor.Execute())

		// Still only one file
		files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
		require.NoError(t, err)
		assert.Len(t, files, 1)

		// File is larger (more data)
		info2, err := os.Stat(latestFile)
		require.NoError(t, err)
		assert.Greater(t, info2.Size(), size1)
	})

	t.Run("skips empty database", func(t *testing.T) {
		emptyDir := filepath.Join(testDir, "empty_backups")
		emptyDB := openTestDB(t, filepath.Join(testDir, "emptydb"), encKey)
		defer emptyDB.Close()

		emptyExec := NewBadgerBackupExecutor("empty", emptyDB, backupKey, emptyDir)
		require.NoError(t, emptyExec.Execute())

		_, err := os.Stat(filepath.Join(emptyDir, "backup-empty-latest.enc"))
		assert.True(t, os.IsNotExist(err), "no file should be created for empty DB")
	})
}

// ── Metadata ───────────────────────────────────────────────────────────────────

func TestBadgerBackupExecutor_Metadata(t *testing.T) {
	testDir := t.TempDir()
	encKey, backupKey := generateTestKeys()
	db := openTestDB(t, filepath.Join(testDir, "db"), encKey)
	defer db.Close()

	executor := NewBadgerBackupExecutor("node0", db, backupKey, filepath.Join(testDir, "backups"))

	require.NoError(t, db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("key"), []byte("value"))
	}))
	require.NoError(t, executor.Execute())

	latestFile := filepath.Join(testDir, "backups", "backup-node0-latest.enc")

	t.Run("file has correct metadata", func(t *testing.T) {
		meta, err := executor.parseBackupMetadata(latestFile)
		require.NoError(t, err)
		assert.Equal(t, "AES-256-GCM", meta.Algo)
		assert.NotEmpty(t, meta.NonceB64)
		assert.NotEmpty(t, meta.CreatedAt)
		assert.NotEmpty(t, meta.EncryptionKeyID)
	})

	t.Run("file is encrypted", func(t *testing.T) {
		data, err := os.ReadFile(latestFile)
		require.NoError(t, err)
		assert.True(t, len(data) >= len(magic))
		assert.Equal(t, magic, string(data[:len(magic)]))
		assert.NotContains(t, string(data), "value")
	})

	t.Run("filename follows expected pattern", func(t *testing.T) {
		assert.Equal(t, "backup-node0-latest.enc", filepath.Base(latestFile))
	})
}

// ── File format ────────────────────────────────────────────────────────────────

func TestBadgerBackupExecutor_FileFormat(t *testing.T) {
	testDir := t.TempDir()
	encKey, backupKey := generateTestKeys()
	db := openTestDB(t, filepath.Join(testDir, "db"), encKey)
	defer db.Close()

	executor := NewBadgerBackupExecutor("node0", db, backupKey, filepath.Join(testDir, "backups"))

	require.NoError(t, db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("k"), []byte("v"))
	}))
	require.NoError(t, executor.Execute())

	data, err := os.ReadFile(filepath.Join(testDir, "backups", "backup-node0-latest.enc"))
	require.NoError(t, err)

	assert.True(t, len(data) >= len(magic)+4)
	assert.Equal(t, magic, string(data[:len(magic)]))

	metaLen := binary.BigEndian.Uint32(data[len(magic) : len(magic)+4])
	assert.Greater(t, metaLen, uint32(0))
	assert.Less(t, int(metaLen), len(data)-len(magic)-4)
}

// ── Restore ────────────────────────────────────────────────────────────────────

func TestBadgerBackupExecutor_Restore(t *testing.T) {
	testDir := t.TempDir()
	encKey, backupKey := generateTestKeys()
	db := openTestDB(t, filepath.Join(testDir, "db"), encKey)

	executor := NewBadgerBackupExecutor("node0", db, backupKey, filepath.Join(testDir, "backups"))

	// Write data in multiple rounds, backup each time — only latest matters
	for _, kv := range [][2]string{{"k1", "v1"}, {"k2", "v2"}, {"k3", "v3"}} {
		require.NoError(t, db.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte(kv[0]), []byte(kv[1]))
		}))
		require.NoError(t, executor.Execute())
	}
	db.Close()

	restorePath := filepath.Join(testDir, "restored")

	t.Run("restores all data from single file", func(t *testing.T) {
		require.NoError(t, executor.RestoreBackup(restorePath, encKey))

		rdb := openTestDB(t, restorePath, encKey)
		defer rdb.Close()

		for _, kv := range [][2]string{{"k1", "v1"}, {"k2", "v2"}, {"k3", "v3"}} {
			var val []byte
			require.NoError(t, rdb.View(func(txn *badger.Txn) error {
				item, err := txn.Get([]byte(kv[0]))
				if err != nil {
					return err
				}
				return item.Value(func(v []byte) error {
					val = append([]byte{}, v...)
					return nil
				})
			}))
			assert.Equal(t, kv[1], string(val))
		}
	})

	t.Run("restore fails when backup file is missing", func(t *testing.T) {
		emptyDir := filepath.Join(testDir, "no_backups")
		require.NoError(t, os.MkdirAll(emptyDir, 0700))

		emptyExec := NewBadgerBackupExecutor("node0", nil, backupKey, emptyDir)
		err := emptyExec.RestoreBackup(filepath.Join(testDir, "empty_restored"), encKey)
		require.Error(t, err)
	})
}

// ── Integration ────────────────────────────────────────────────────────────────

func TestBadgerKVStore_BackupIntegration(t *testing.T) {
	testDir := t.TempDir()
	encKey, backupKey := generateTestKeys()

	store, err := NewBadgerKVStore(BadgerConfig{
		NodeID:              "node0",
		EncryptionKey:       encKey,
		BackupEncryptionKey: backupKey,
		BackupDir:           filepath.Join(testDir, "backups"),
		DBPath:              filepath.Join(testDir, "db"),
	})
	require.NoError(t, err)
	defer store.Close()

	t.Run("backup overwrites single file across multiple calls", func(t *testing.T) {
		require.NoError(t, store.Put("k1", []byte("v1")))
		require.NoError(t, store.Backup())

		require.NoError(t, store.Put("k2", []byte("v2")))
		require.NoError(t, store.Put("k3", []byte("v3")))
		require.NoError(t, store.Backup())

		files, err := filepath.Glob(filepath.Join(testDir, "backups", "backup-*.enc"))
		require.NoError(t, err)
		assert.Len(t, files, 1, "should always be exactly one backup file")
		assert.Equal(t, "backup-node0-latest.enc", filepath.Base(files[0]))

		for _, kv := range [][2]string{{"k1", "v1"}, {"k2", "v2"}, {"k3", "v3"}} {
			val, err := store.Get(kv[0])
			require.NoError(t, err)
			assert.Equal(t, kv[1], string(val))
		}
	})

	t.Run("backup without executor returns error", func(t *testing.T) {
		store.BackupExecutor = nil
		err := store.Backup()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "backup executor is not initialized")
	})
}

// ── parseBackupMetadata helper ─────────────────────────────────────────────────

func (b *badgerBackupExecutor) parseBackupMetadata(path string) (BadgerBackupMeta, error) {
	var meta BadgerBackupMeta
	f, err := os.Open(path)
	if err != nil {
		return meta, err
	}
	defer f.Close()

	magicBuf := make([]byte, len(magic))
	if _, err := f.Read(magicBuf); err != nil {
		return meta, err
	}

	var metaLen uint32
	if err := binary.Read(f, binary.BigEndian, &metaLen); err != nil {
		return meta, err
	}

	metaBuf := make([]byte, metaLen)
	if _, err := f.Read(metaBuf); err != nil {
		return meta, err
	}

	err = json.Unmarshal(metaBuf, &meta)
	return meta, err
}
