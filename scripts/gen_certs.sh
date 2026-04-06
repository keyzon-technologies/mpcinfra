#!/bin/bash
# gen_certs.sh — Generates a local CA + TLS certs for NATS (mTLS) and Consul (TLS)
# Output: certs/  (gitignored)
#
# Usage:
#   bash scripts/gen_certs.sh
#
# Requires: openssl

set -euo pipefail

CERTS_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "Generating TLS certificates in: $(pwd)"

# ── Root CA ────────────────────────────────────────────────────────────────────
echo "[1/7] Root CA"
openssl genrsa -out rootCA.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 \
  -subj "/C=BR/O=mpcinfra/CN=mpcinfra-root-ca" \
  -out rootCA.pem

# ── NATS Server cert ───────────────────────────────────────────────────────────
echo "[2/7] NATS server cert"
openssl genrsa -out nats-server.key 2048 2>/dev/null
openssl req -new -key nats-server.key \
  -subj "/C=BR/O=mpcinfra/CN=nats-server" \
  -out nats-server.csr
openssl x509 -req -in nats-server.csr -CA rootCA.pem -CAkey rootCA.key \
  -CAcreateserial -out nats-server.pem -days 730 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost,DNS:nats-server,IP:127.0.0.1")

# ── NATS Client cert (mTLS) ────────────────────────────────────────────────────
echo "[3/7] NATS client cert"
openssl genrsa -out nats-client.key 2048 2>/dev/null
openssl req -new -key nats-client.key \
  -subj "/C=BR/O=mpcinfra/CN=nats-client" \
  -out nats-client.csr
openssl x509 -req -in nats-client.csr -CA rootCA.pem -CAkey rootCA.key \
  -CAcreateserial -out nats-client.pem -days 730 -sha256

# ── Consul Server cert ─────────────────────────────────────────────────────────
echo "[4/7] Consul server cert"
openssl genrsa -out consul-server.key 2048 2>/dev/null
openssl req -new -key consul-server.key \
  -subj "/C=BR/O=mpcinfra/CN=consul-server" \
  -out consul-server.csr
openssl x509 -req -in consul-server.csr -CA rootCA.pem -CAkey rootCA.key \
  -CAcreateserial -out consul-server.pem -days 730 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost,DNS:consul,IP:127.0.0.1")

# ── Consul Client cert ─────────────────────────────────────────────────────────
echo "[5/7] Consul client cert"
openssl genrsa -out consul-client.key 2048 2>/dev/null
openssl req -new -key consul-client.key \
  -subj "/C=BR/O=mpcinfra/CN=consul-client" \
  -out consul-client.csr
openssl x509 -req -in consul-client.csr -CA rootCA.pem -CAkey rootCA.key \
  -CAcreateserial -out consul-client.pem -days 730 -sha256

# ── Rename to expected paths ───────────────────────────────────────────────────
echo "[6/7] Setting up default cert paths"
# NATS default paths (used by GetNATSConnection fallback)
cp nats-client.pem client-cert.pem
cp nats-client.key client-key.pem
# Consul default paths (used by loadConsulTLSConfig fallback)
cp consul-client.pem consul-client-cert.pem
cp consul-client.key consul-client-key.pem
cp rootCA.pem consul-rootCA.pem

# ── Permissions ────────────────────────────────────────────────────────────────
echo "[7/7] Setting permissions"
chmod 600 *.key
chmod 644 *.pem

# ── Cleanup CSR/serial files ───────────────────────────────────────────────────
rm -f *.csr *.srl

echo ""
echo "Certificates generated in: $(pwd)"
echo ""
echo "  rootCA.pem              — Root CA certificate"
echo "  nats-server.{pem,key}   — NATS server TLS"
echo "  nats-client.{pem,key}   — NATS client mTLS"
echo "  consul-server.{pem,key} — Consul server TLS"
echo "  consul-client.{pem,key} — Consul client TLS"
echo ""
echo "Default fallback paths configured:"
echo "  certs/client-cert.pem         (NATS client cert)"
echo "  certs/client-key.pem          (NATS client key)"
echo "  certs/consul-client-cert.pem  (Consul client cert)"
echo "  certs/consul-client-key.pem   (Consul client key)"
echo "  certs/consul-rootCA.pem       (Consul CA)"
