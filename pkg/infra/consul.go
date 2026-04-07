package infra

import (
	"crypto/tls"
	"net/http"
	"strconv"
	"time"

	"github.com/hashicorp/consul/api"
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
	cfg.Token = viper.GetString("consul.token")
	cfg.WaitTime = 10 * time.Second

	tokenLength := 0
	if cfg.Token != "" {
		tokenLength = len(cfg.Token)
	}

	logger.Info("Consul config",
		"environment", environment,
		"address", cfg.Address,
		"wait_time", cfg.WaitTime,
		"token_length", tokenLength,
	)

	if environment == constant.EnvProduction {
		tlsCfg := buildConsulTLSConfig()
		cfg.Scheme = "https"
		cfg.HttpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		}
	}

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

// buildConsulTLSConfig builds a *tls.Config from base64 env vars.
// Bypasses api.TLSConfig to avoid version-specific PEM field issues.
func buildConsulTLSConfig() *tls.Config {
	certB64 := viper.GetString("consul.tls.client_cert_b64")
	keyB64 := viper.GetString("consul.tls.client_key_b64")
	caB64 := viper.GetString("consul.tls.ca_b64")

	if certB64 == "" || keyB64 == "" || caB64 == "" {
		logger.Fatal(
			"Missing required Consul TLS base64 env vars: "+
				"CONSUL_CLIENT_CERT="+strconv.FormatBool(certB64 != "")+
				", CONSUL_CLIENT_KEY="+strconv.FormatBool(keyB64 != "")+
				", TLS_CA="+strconv.FormatBool(caB64 != ""),
			nil,
		)
	}

	pems, err := LoadTLSPEMs(certB64, keyB64, caB64)
	if err != nil {
		logger.Fatal("Failed to decode Consul TLS base64 certs", err)
	}

	tlsCfg, err := pems.TLSConfig()
	if err != nil {
		logger.Fatal("Failed to build Consul TLS config", err)
	}

	return tlsCfg
}
