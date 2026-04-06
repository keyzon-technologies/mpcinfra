package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/keyzon-technologies/mpcinfra/pkg/config"
	"github.com/keyzon-technologies/mpcinfra/pkg/encryption"
	"github.com/keyzon-technologies/mpcinfra/pkg/infra"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

func recoverConsul(ctx context.Context, c *cli.Command) error {
	nodeName := c.String("node")
	environment := c.String("environment")
	force := c.Bool("force")

	config.InitViperConfig()
	logger.Init(environment, false)
	appConfig := config.LoadConfig()

	if !appConfig.R2.IsEnabled() {
		return fmt.Errorf("R2 is not configured — set R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY and R2_BUCKET")
	}

	// ── Prompt for password ──────────────────────────────────────────────────
	fmt.Print("Enter Consul backup password (CONSUL_BACKUP_PASSWORD): ")
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil || len(passBytes) == 0 {
		return fmt.Errorf("backup password is required")
	}
	encKey := encryption.DeriveKey(string(passBytes), "mpcinfra-consul-backup")

	// ── List backups from R2 ─────────────────────────────────────────────────
	r2Prefix := appConfig.R2.Prefix
	if r2Prefix == "" {
		r2Prefix = nodeName + "/"
	}
	consulPrefix := r2Prefix + "consul/"

	r2, err := kvstore.NewR2Uploader(
		appConfig.R2.AccountID,
		appConfig.R2.AccessKeyID,
		appConfig.R2.SecretAccessKey,
		appConfig.R2.Bucket,
		consulPrefix,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize R2 client: %w", err)
	}

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	keys, err := r2.ListObjects(listCtx)
	if err != nil {
		return fmt.Errorf("failed to list R2 objects: %w", err)
	}

	// Filter only consul backup files for this node
	var backupKeys []string
	for _, k := range keys {
		if strings.Contains(k, fmt.Sprintf("consul-backup-%s-", nodeName)) && strings.HasSuffix(k, ".enc") {
			backupKeys = append(backupKeys, k)
		}
	}

	if len(backupKeys) == 0 {
		return fmt.Errorf("no Consul backup files found in R2 for node %q (prefix: %s)", nodeName, consulPrefix)
	}

	// Sort ascending — last entry is the most recent
	sort.Strings(backupKeys)
	latestKey := backupKeys[len(backupKeys)-1]

	fmt.Printf("Found %d backup(s). Latest: %s\n", len(backupKeys), latestKey)

	// ── Confirm ──────────────────────────────────────────────────────────────
	if !force {
		fmt.Printf("This will overwrite existing Consul KV data. Continue? [y/N]: ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// ── Download ─────────────────────────────────────────────────────────────
	fmt.Printf("Downloading %s...\n", latestKey)
	dlCtx, dlCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer dlCancel()

	fileBytes, err := r2.Download(dlCtx, latestKey)
	if err != nil {
		return fmt.Errorf("failed to download backup: %w", err)
	}
	fmt.Printf("Downloaded %d bytes\n", len(fileBytes))

	// ── Restore to Consul ────────────────────────────────────────────────────
	consulClient := infra.GetConsulClient(environment)
	kv := consulClient.KV()

	if err := infra.RestoreConsulBackupFromBytes(fileBytes, kv, encKey); err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}

	fmt.Printf("✅ Consul KV restore completed successfully from %s\n", latestKey)
	return nil
}
