package main

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/keyzon-technologies/mpcinfra/pkg/encryption"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

// recoverDatabase handles the database recovery from encrypted backup files
func recoverDatabase(ctx context.Context, c *cli.Command) error {
	backupDir := c.String("backup-dir")
	recoveryPath := c.String("recovery-path")
	force := c.Bool("force")

	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return fmt.Errorf("backup directory does not exist: %s", backupDir)
	}

	if _, err := os.Stat(recoveryPath); err == nil && !force {
		return fmt.Errorf("recovery path already exists: %s (use --force to overwrite)", recoveryPath)
	}

	// Prompt for backup encryption password
	fmt.Print("Enter backup password (BADGER_BACKUP_PASSWORD): ")
	backupPassBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read backup password: %w", err)
	}
	fmt.Println()
	if len(backupPassBytes) == 0 {
		return fmt.Errorf("backup password cannot be empty")
	}

	// Prompt for DB encryption password (used to open the restored database)
	fmt.Print("Enter DB password (BADGER_PASSWORD): ")
	dbPassBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read DB password: %w", err)
	}
	fmt.Println()
	if len(dbPassBytes) == 0 {
		return fmt.Errorf("DB password cannot be empty")
	}

	// Derive keys using the same KDF + contexts used during backup creation.
	backupKey := encryption.DeriveKey(string(backupPassBytes), "mpcinfra-badger-backup")
	dbKey := encryption.DeriveKey(string(dbPassBytes), "mpcinfra-badger-db")

	// Remove existing recovery path if force flag is set
	if force {
		if err := os.RemoveAll(recoveryPath); err != nil {
			return fmt.Errorf("failed to remove existing recovery path: %w", err)
		}
	}

	fmt.Printf("Starting database recovery...\n")
	fmt.Printf("Backup directory: %s\n", backupDir)
	fmt.Printf("Recovery path: %s\n", recoveryPath)

	// backupKey decrypts the AES-GCM backup files; dbKey encrypts the restored BadgerDB.
	tempExecutor := kvstore.NewBadgerBackupExecutor("temp", nil, backupKey, backupDir)

	if err := tempExecutor.RestoreAllBackupsEncrypted(recoveryPath, dbKey); err != nil {
		return fmt.Errorf("recovery failed: %w", err)
	}

	fmt.Printf("✅ Database recovery completed successfully!\n")
	fmt.Printf("Restored database is available at: %s\n", recoveryPath)
	return nil
}
