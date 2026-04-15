package main

import (
	"context"
	"fmt"
	"os"
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

	// ── Locate backup in R2 ──────────────────────────────────────────────────
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

	latestKey := r2Prefix + fmt.Sprintf("backup-%s-latest.enc", nodeName)
	fmt.Printf("Downloading %s...\n", latestKey)

	// ── Confirm ──────────────────────────────────────────────────────────────
	if !force {
		fmt.Printf("Restore to %s? [y/N]: ", recoveryPath)
		var answer string
		if _, err := fmt.Scanln(&answer); err != nil {
			answer = ""
		}
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// ── Download ─────────────────────────────────────────────────────────────
	dlCtx, dlCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer dlCancel()

	fileBytes, err := r2.Download(dlCtx, latestKey)
	if err != nil {
		return fmt.Errorf("failed to download backup: %w", err)
	}
	fmt.Printf("Downloaded %d bytes\n", len(fileBytes))

	// ── Restore ──────────────────────────────────────────────────────────────
	if force {
		if err := os.RemoveAll(recoveryPath); err != nil {
			return fmt.Errorf("failed to remove existing recovery path: %w", err)
		}
	}

	executor := kvstore.NewBadgerBackupExecutor(nodeName, nil, backupKey, ".")
	if err := executor.RestoreBackupFromBytes(recoveryPath, fileBytes, dbKey); err != nil {
		return fmt.Errorf("recovery failed: %w", err)
	}

	fmt.Printf("✅ Badger database restored successfully to: %s\n", recoveryPath)
	return nil
}
