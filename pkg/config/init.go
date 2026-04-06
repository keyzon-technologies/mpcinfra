package config

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/joho/godotenv"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type AppConfig struct {
	Consul *ConsulConfig `mapstructure:"consul"`
	NATs   *NATsConfig   `mapstructure:"nats"`
	R2     *R2Config     `mapstructure:"r2"`

	Environment           string `mapstructure:"environment"`
	BadgerPassword        string `mapstructure:"badger_password"`
	BadgerBackupPassword  string `mapstructure:"badger_backup_password"`
	ConsulBackupPassword  string `mapstructure:"consul_backup_password"`
	ChainCodeHex          string `mapstructure:"chain_code"`
}

// R2Config holds Cloudflare R2 credentials for off-site backup uploads.
// Set via env vars: R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET, R2_PREFIX (optional).
type R2Config struct {
	AccountID       string `mapstructure:"account_id"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
	Bucket          string `mapstructure:"bucket"`
	Prefix          string `mapstructure:"prefix"`
}

func (r *R2Config) IsEnabled() bool {
	return r != nil &&
		r.AccountID != "" &&
		r.AccessKeyID != "" &&
		r.SecretAccessKey != "" &&
		r.Bucket != ""
}

// Implement masking serializer AppConfig
func (c AppConfig) MarshalJSONMask() string {
	// clone app config
	c.BadgerPassword = strings.Repeat("*", len(c.BadgerPassword))
	c.BadgerBackupPassword = strings.Repeat("*", len(c.BadgerBackupPassword))
	c.Consul.Password = strings.Repeat("*", len(c.Consul.Password))
	c.Consul.Token = strings.Repeat("*", len(c.Consul.Token))
	if c.Consul.TLS != nil {
		consulTLSCopy := *c.Consul.TLS
		c.Consul.TLS = &consulTLSCopy
	}
	c.NATs.Password = strings.Repeat("*", len(c.NATs.Password))
	if c.R2 != nil {
		r2Copy := *c.R2
		r2Copy.SecretAccessKey = strings.Repeat("*", len(r2Copy.SecretAccessKey))
		r2Copy.AccessKeyID = strings.Repeat("*", len(r2Copy.AccessKeyID))
		c.R2 = &r2Copy
	}

	bytes, err := json.Marshal(c)
	if err != nil {
		logger.Error("Failed to marshal app config", err)
	}
	return string(bytes)
}

type ConsulConfig struct {
	Address  string           `mapstructure:"address"`
	Username string           `mapstructure:"username"`
	Password string           `mapstructure:"password"`
	Token    string           `mapstructure:"token"`
	TLS      *ConsulTLSConfig `mapstructure:"tls"`
}

type ConsulTLSConfig struct {
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`
	CACert     string `mapstructure:"ca_cert"`
}

type NATsConfig struct {
	URL      string     `mapstructure:"url"`
	Username string     `mapstructure:"username"`
	Password string     `mapstructure:"password"`
	TLS      *TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`
	CACert     string `mapstructure:"ca_cert"`
}

func InitViperConfig() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalln(err.Error())
	}

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.BindEnv("environment", "ENVIRONMENT")
	viper.BindEnv("badger_password", "BADGER_PASSWORD")
	viper.BindEnv("badger_backup_password", "BADGER_BACKUP_PASSWORD")
	viper.BindEnv("consul_backup_password", "CONSUL_BACKUP_PASSWORD")
	viper.BindEnv("chain_code", "CHAIN_CODE")
	viper.BindEnv("consul.address", "CONSUL_ADDRESS")
	viper.BindEnv("consul.username", "CONSUL_USERNAME")
	viper.BindEnv("consul.password", "CONSUL_PASSWORD")
	viper.BindEnv("consul.token", "CONSUL_TOKEN")
	viper.BindEnv("consul.tls.client_cert", "CONSUL_TLS_CLIENT_CERT")
	viper.BindEnv("consul.tls.client_key", "CONSUL_TLS_CLIENT_KEY")
	viper.BindEnv("consul.tls.ca_cert", "CONSUL_TLS_CA_CERT")
	viper.BindEnv("nats.url", "NATS_URL")
	viper.BindEnv("nats.username", "NATS_USERNAME")
	viper.BindEnv("nats.password", "NATS_PASSWORD")
	viper.BindEnv("nats.tls.client_cert", "NATS_TLS_CLIENT_CERT")
	viper.BindEnv("nats.tls.client_key", "NATS_TLS_CLIENT_KEY")
	viper.BindEnv("nats.tls.ca_cert", "NATS_TLS_CA_CERT")
	viper.BindEnv("r2.account_id", "R2_ACCOUNT_ID")
	viper.BindEnv("r2.access_key_id", "R2_ACCESS_KEY_ID")
	viper.BindEnv("r2.secret_access_key", "R2_SECRET_ACCESS_KEY")
	viper.BindEnv("r2.bucket", "R2_BUCKET")
	viper.BindEnv("r2.prefix", "R2_PREFIX")

	log.Println("Initialized config from environment variables")
}

func LoadConfig() *AppConfig {
	var config AppConfig
	decoderConfig := &mapstructure.DecoderConfig{
		Result:           &config,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		log.Fatal("Failed to create decoder", err)
	}

	if err := decoder.Decode(viper.AllSettings()); err != nil {
		log.Fatal("Failed to decode config", err)
	}

	if err := validateEnvironment(config.Environment); err != nil {
		log.Fatal("Config validation failed:", err)
	}

	return &config
}

func validateEnvironment(environment string) error {
	validEnvironments := []string{"production", "development"}

	for _, validEnv := range validEnvironments {
		if environment == validEnv {
			return nil
		}
	}

	return fmt.Errorf("invalid environment '%s'. Must be one of: %s", environment, strings.Join(validEnvironments, ", "))
}
