#!/bin/bash
set -euo pipefail

# Number of nodes to create (default is 3)
NUM_NODES=3

echo "🚀 Setting up Node Identities..."

# Preconditions
command -v mpcinfra-cli >/dev/null 2>&1 || { echo "❌ mpcinfra-cli not found in PATH"; exit 1; }
[ -f .env ] || { echo "❌ .env not found in repo root (copy from .env.example)"; exit 1; }

if [ ! -f peers.json ]; then
    echo "❌ peers.json not found in repo root"
    echo ""
    echo "📝 Please generate peers.json first by running:"
    echo "   mpcinfra-cli generate-peers -n $NUM_NODES"
    exit 1
fi

# ── Helpers ────────────────────────────────────────────────────────────────────

# Read a value from a .env file: env_get <file> <KEY>
env_get() {
    grep -E "^${2}=" "$1" | head -1 | sed -E 's/^[^=]+=["'"'"']?([^"'"'"']*)["'"'"']?$/\1/'
}

# Set or add a key in a .env file: env_set <file> <KEY> <value>
env_set() {
    local file="$1" key="$2" val="$3"
    if grep -qE "^${key}=" "$file"; then
        sed -i -E "s|^(${key}=).*|\1\"${val}\"|" "$file"
    else
        printf '\n%s="%s"\n' "$key" "$val" >> "$file"
    fi
}

# ── Create node directories ────────────────────────────────────────────────────
echo "📁 Creating node directories..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "node$i/identity"
    if [ ! -f "node$i/.env" ]; then
        cp .env "node$i/.env"
    fi
    if [ ! -f "node$i/peers.json" ]; then
        cp peers.json "node$i/"
    fi
done

# ── Generate identities ────────────────────────────────────────────────────────
echo "🔑 Generating identities for each node..."
for i in $(seq 0 $((NUM_NODES-1))); do
    echo "📝 Generating identity for node$i..."
    ( cd "node$i" && mpcinfra-cli generate-identity --node "node$i" )
done

# ── Chain code ─────────────────────────────────────────────────────────────────
# Use CHAIN_CODE from root .env if already set; otherwise generate one.
EXISTING_CC=$(env_get .env CHAIN_CODE)
if [ -n "$EXISTING_CC" ] && [ "$EXISTING_CC" != "your-32-byte-hex-chain-code-here" ]; then
    CC="$EXISTING_CC"
    echo "🔐 Using existing CHAIN_CODE from .env"
elif [ -f .chain_code ]; then
    CC=$(cat .chain_code)
    echo "🔐 Using CHAIN_CODE from .chain_code file"
else
    echo "🔐 Generating CHAIN_CODE (32-byte hex)..."
    CC=$(openssl rand -hex 32)
    echo "$CC" > .chain_code
fi

if [ -z "$CC" ]; then
    echo "❌ Failed to determine chain_code"
    exit 1
fi

echo "📝 Setting CHAIN_CODE in root .env..."
env_set .env CHAIN_CODE "$CC"

echo "📦 Distributing CHAIN_CODE to node .env files..."
for i in $(seq 0 $((NUM_NODES-1))); do
    env_set "node$i/.env" CHAIN_CODE "$CC"
done

# ── Event initiator public key ─────────────────────────────────────────────────
if [ -f "event_initiator.identity.json" ]; then
    INITIATOR_PUBKEY=$(grep -o '"public_key": *"[^"]*"' event_initiator.identity.json | cut -d '"' -f4)
    if [ -n "${INITIATOR_PUBKEY}" ]; then
        echo "📦 Distributing EVENT_INITIATOR_PUBKEY to node .env files..."
        for i in $(seq 0 $((NUM_NODES-1))); do
            env_set "node$i/.env" EVENT_INITIATOR_PUBKEY "$INITIATOR_PUBKEY"
        done
    fi
fi

# ── Distribute identity files ──────────────────────────────────────────────────
echo "🔄 Distributing identity files across nodes..."
for i in $(seq 0 $((NUM_NODES-1))); do
    src="node$i/identity/node${i}_identity.json"
    [ -f "$src" ] || { echo "❌ Missing identity file for node$i at $src"; exit 1; }
    for j in $(seq 0 $((NUM_NODES-1))); do
        if [ "$i" != "$j" ]; then
            mkdir -p "node$j/identity"
            echo "📋 Copying node${i}_identity.json to node$j..."
            cp -f "$src" "node$j/identity/"
        fi
    done
done

echo "✨ Node identities setup complete!"
echo
echo "📂 Created folder structure:"
echo "├── node0"
echo "│   ├── .env"
echo "│   ├── identity/"
echo "│   └── peers.json"
echo "├── node1"
echo "│   ├── .env"
echo "│   ├── identity/"
echo "│   └── peers.json"
echo "└── node2"
echo "    ├── .env"
echo "    ├── identity/"
echo "    └── peers.json"
echo
echo "✅ You can now start your nodes with:"
echo "cd node0 && mpcinfra start -n node0"
echo "cd node1 && mpcinfra start -n node1"
echo "cd node2 && mpcinfra start -n node2"
