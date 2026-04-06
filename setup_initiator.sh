#!/bin/bash
set -euo pipefail

echo "🚀 Setting up Event Initiator..."

# Preconditions
command -v mpcinfra-cli >/dev/null 2>&1 || { echo "❌ mpcinfra-cli not found in PATH"; exit 1; }
[ -f .env ] || { echo "❌ .env not found in repo root (copy from .env.example)"; exit 1; }

# env_set <file> <KEY> <value>
env_set() {
    local file="$1" key="$2" val="$3"
    if grep -qE "^${key}=" "$file"; then
        sed -i -E "s|^(${key}=).*|\1\"${val}\"|" "$file"
    else
        printf '\n%s="%s"\n' "$key" "$val" >> "$file"
    fi
}

# Generate the event initiator
echo "📝 Generating event initiator..."
mpcinfra-cli generate-initiator

# Extract and distribute the public key
if [ ! -f "event_initiator.identity.json" ]; then
    echo "❌ event_initiator.identity.json not found"
    exit 1
fi

PUBLIC_KEY=$(grep -o '"public_key": *"[^"]*"' event_initiator.identity.json | cut -d '"' -f4)

if [ -z "${PUBLIC_KEY}" ]; then
    echo "❌ Could not extract public key from event_initiator.identity.json"
    exit 1
fi

echo "🔑 Found public key: ${PUBLIC_KEY}"

echo "📝 Updating root .env..."
env_set .env EVENT_INITIATOR_PUBKEY "$PUBLIC_KEY"
echo "✅ Root .env updated"

# Update any existing node .env files
for node_env in node*/.env; do
    [ -f "$node_env" ] || continue
    echo "📝 Updating ${node_env}..."
    env_set "$node_env" EVENT_INITIATOR_PUBKEY "$PUBLIC_KEY"
done

echo "✨ Event Initiator setup complete!"
