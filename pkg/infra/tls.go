package infra

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

type TLSPEMs struct {
	CertPEM []byte
	KeyPEM  []byte
	CAPEM   []byte
}

// LoadTLSPEMs loads TLS material either from base64-encoded strings (cloud/production)
func LoadTLSPEMs(certB64, keyB64, caB64 string) (*TLSPEMs, error) {
	certPEM, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, fmt.Errorf("decode cert base64: %w", err)
	}
	keyPEM, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("decode key base64: %w", err)
	}
	caPEM, err := base64.StdEncoding.DecodeString(caB64)
	if err != nil {
		return nil, fmt.Errorf("decode CA base64: %w", err)
	}
	return &TLSPEMs{CertPEM: certPEM, KeyPEM: keyPEM, CAPEM: caPEM}, nil
}

// TLSConfig builds a *tls.Config from the loaded PEM material.
func (p *TLSPEMs) TLSConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(p.CertPEM, p.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(p.CAPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
	}, nil
}
