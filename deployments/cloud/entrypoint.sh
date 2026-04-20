#!/bin/sh
set -euo pipefail

: "${NODE_NAME:?NODE_NAME is required (e.g., node0)}"

mkdir -p /app/identity /app/backups

# Helper: decode base64 env var -> file (if the variable exists and is not empty)
write_b64() {
  var_name="$1"; dest="$2"
  val=$(printenv "$var_name" || true)
  [ -z "$val" ] && return 0
  printf '%s' "$val" | base64 -d > "$dest"
  chmod 600 "$dest"
}

# Public files (same across all nodes)
write_b64 PEERS_JSON_B64           /app/peers.json
write_b64 NODE0_IDENTITY_B64       /app/identity/node0_identity.json
write_b64 NODE1_IDENTITY_B64       /app/identity/node1_identity.json
write_b64 NODE2_IDENTITY_B64       /app/identity/node2_identity.json

# Private key — only for the current node (varies per service on Railway)
write_b64 NODE_PRIVATE_KEY_B64     "/app/identity/${NODE_NAME}_private.key"

exec /app/mpcinfra start -n "$NODE_NAME"