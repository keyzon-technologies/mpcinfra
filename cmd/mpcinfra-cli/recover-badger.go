package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/keyzon-technologies/mpcinfra/pkg/config"
	"github.com/keyzon-technologies/mpcinfra/pkg/encryption"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

func recoverBadgerFromR2(ctx context.Context, c *cli.Command) error {
	nodeName := c.String("node")
	recoveryPath := c.String("recovery-path")
	environment := c.String("environment")
	force := c.Bool("force")

	config.InitViperConfig()
	logger.Init(environment, false)
	appConfig := config.LoadConfig()

	if !appConfig.R2.IsEnabled() {
		return fmt.Errorf("R2 is not configured — set R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY and R2_BUCKET")
	}

	// ── Check recovery path ──────────────────────────────────────────────────
	if _, err := os.Stat(recoveryPath); err == nil && !force {
		return fmt.Errorf("recovery path already exists: %s (use --force to overwrite)", recoveryPath)
	}

	// ── Prompt for passwords ─────────────────────────────────────────────────
	fmt.Print("Enter backup password (BADGER_BACKUP_PASSWORD): ")
	backupPassBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil || len(backupPassBytes) == 0 {
		return fmt.Errorf("backup password is required")
	}

	fmt.Print("Enter DB password (BADGER_PASSWORD): ")
	dbPassBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil || len(dbPassBytes) == 0 {
		return fmt.Errorf("DB password is required")
	}

	backupKey := encryption.DeriveKey(string(backupPassBytes), "mpcinfra-badger-backup")
	dbKey := encryption.DeriveKey(string(dbPassBytes), "mpcinfra-badger-db")

	// ── List backups from R2 ─────────────────────────────────────────────────
	r2Prefix := appConfig.R2.Prefix
	if r2Prefix == "" {
		r2Prefix = nodeName + "/"
	}

	r2, err := kvstore.NewR2Uploader(
		appConfig.R2.AccountID,
		appConfig.R2.AccessKeyID,
		appConfig.R2.SecretAccessKey,
		appConfig.R2.Bucket,
		r2Prefix,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize R2 client: %w", err)
	}

	listCtx, listCancel := context.WithTimeout(ctx, 30*time.Second)
	defer listCancel()

	keys, err := r2.ListObjects(listCtx)
	if err != nil {
		return fmt.Errorf("failed to list R2 objects: %w", err)
	}

	// Filter only Badger backup files for this node (exclude consul/ subfolder)
	var backupKeys []string
	for _, k := range keys {
		if strings.Contains(k, fmt.Sprintf("backup-%s-", nodeName)) &&
			strings.HasSuffix(k, ".enc") &&
			!strings.Contains(k, "consul/") {
			backupKeys = append(backupKeys, k)
		}
	}

	if len(backupKeys) == 0 {
		return fmt.Errorf("no Badger backup files found in R2 for node %q (prefix: %s)", nodeName, r2Prefix)
	}

	sort.Strings(backupKeys)
	fmt.Printf("Found %d backup(s). Will download all for incremental restore.\n", len(backupKeys))
	for _, k := range backupKeys {
		fmt.Printf("  %s\n", k)
	}

	// ── Confirm ──────────────────────────────────────────────────────────────
	if !force {
		fmt.Printf("Restore %d backup(s) to %s? [y/N]: ", len(backupKeys), recoveryPath)
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// ── Download all backups into a temp dir ─────────────────────────────────
	tmpDir, err := os.MkdirTemp("", "mpcinfra-badger-restore-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, key := range backupKeys {
		filename := filepath.Base(key)
		fmt.Printf("Downloading %s...\n", filename)

		dlCtx, dlCancel := context.WithTimeout(ctx, 2*time.Minute)
		data, err := r2.Download(dlCtx, key)
		dlCancel()
		if err != nil {
			return fmt.Errorf("failed to download %s: %w", filename, err)
		}

		localPath := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(localPath, data, 0600); err != nil {
			return fmt.Errorf("failed to write %s: %w", localPath, err)
		}
		fmt.Printf("  Downloaded %d bytes → %s\n", len(data), filename)
	}

	// ── Restore using existing executor ─────────────────────────────────────
	if force {
		if err := os.RemoveAll(recoveryPath); err != nil {
			return fmt.Errorf("failed to remove existing recovery path: %w", err)
		}
	}

	fmt.Printf("Restoring database to %s...\n", recoveryPath)
	executor := kvstore.NewBadgerBackupExecutor("temp", nil, backupKey, tmpDir)
	if err := executor.RestoreAllBackupsEncrypted(recoveryPath, dbKey); err != nil {
		return fmt.Errorf("recovery failed: %w", err)
	}

	fmt.Printf("✅ Badger database restored successfully to: %s\n", recoveryPath)
	return nil
}
