package infra

import (
	"path/filepath"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/keyzon-technologies/mpcinfra/pkg/config"
	"github.com/keyzon-technologies/mpcinfra/pkg/constant"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/spf13/viper"
)

type ConsulKV interface {
	Put(kv *api.KVPair, options *api.WriteOptions) (*api.WriteMeta, error)
	Get(key string, options *api.QueryOptions) (*api.KVPair, *api.QueryMeta, error)
	Delete(key string, options *api.WriteOptions) (*api.WriteMeta, error)
	List(prefix string, options *api.QueryOptions) (api.KVPairs, *api.QueryMeta, error)
}

func GetConsulClient(environment string) *api.Client {
	cfg := api.DefaultConfig()
	cfg.Address = viper.GetString("consul.address")
	cfg.WaitTime = 10 * time.Second

	if environment == constant.EnvProduction {
		cfg.Token = viper.GetString("consul.token")
		username := viper.GetString("consul.username")
		password := viper.GetString("consul.password")
		if username != "" || password != "" {
			cfg.HttpAuth = &api.HttpBasicAuth{
				Username: username,
				Password: password,
			}
		}

		// TLS — load from ConsulTLSConfig or fall back to default cert paths
		tlsCfg := loadConsulTLSConfig()
		if tlsCfg.CAFile != "" || tlsCfg.CertFile != "" {
			cfg.TLSConfig = *tlsCfg
		}
	}

	tokenLength := 0
	if cfg.Token != "" {
		tokenLength = len(cfg.Token)
	}
	hasAuth := cfg.HttpAuth != nil
	hasTLS := cfg.TLSConfig.CAFile != "" || cfg.TLSConfig.CertFile != ""

	logger.Info("Consul config",
		"environment", environment,
		"address", cfg.Address,
		"wait_time", cfg.WaitTime,
		"token_length", tokenLength,
		"http_auth", hasAuth,
		"tls", hasTLS,
	)

	client, err := api.NewClient(cfg)
	if err != nil {
		logger.Fatal("Failed to create consul client", err)
	}

	_, err = client.Status().Leader()
	if err != nil {
		logger.Fatal("failed to connect to Consul", err)
	}

	return client
}

// loadConsulTLSConfig reads TLS paths from config/env, falling back to default cert paths.
func loadConsulTLSConfig() *api.TLSConfig {
	var tlsCfg config.ConsulTLSConfig
	if v := viper.GetString("consul.tls.client_cert"); v != "" {
		tlsCfg.ClientCert = v
	}
	if v := viper.GetString("consul.tls.client_key"); v != "" {
		tlsCfg.ClientKey = v
	}
	if v := viper.GetString("consul.tls.ca_cert"); v != "" {
		tlsCfg.CACert = v
	}

	// Fall back to default paths if any field is missing
	if tlsCfg.ClientCert == "" {
		tlsCfg.ClientCert = filepath.Join(".", "certs", "consul-client-cert.pem")
	}
	if tlsCfg.ClientKey == "" {
		tlsCfg.ClientKey = filepath.Join(".", "certs", "consul-client-key.pem")
	}
	if tlsCfg.CACert == "" {
		tlsCfg.CACert = filepath.Join(".", "certs", "consul-rootCA.pem")
	}

	return &api.TLSConfig{
		CertFile: tlsCfg.ClientCert,
		KeyFile:  tlsCfg.ClientKey,
		CAFile:   tlsCfg.CACert,
	}
}
