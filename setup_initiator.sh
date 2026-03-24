#!/bin/bash
set -euo pipefail

echo "🚀 Setting up Event Initiator..."

# Generate the event initiator
echo "📝 Generating event initiator..."
mpcinfra-cli generate-initiator

# Extract the public key from the generated file
if [ -f "event_initiator.identity.json" ]; then
    PUBLIC_KEY=$(grep -o '"public_key": *"[^"]*"' event_initiator.identity.json | cut -d '"' -f4)

    if [ -n "${PUBLIC_KEY}" ]; then
        echo "🔑 Found public key: ${PUBLIC_KEY}"

        # Update config.yaml
        if [ -f "config.yaml" ]; then
            echo "📝 Updating config.yaml..."
            # If key exists, replace the whole line; otherwise append a new line
            if grep -q "^\s*event_initiator_pubkey:" config.yaml; then
                if [[ "${OSTYPE:-}" == darwin* ]]; then
                    sed -i '' -E "s|^([[:space:]]*event_initiator_pubkey:).*|\1 \"${PUBLIC_KEY}\"|" config.yaml
                else
                    sed -i -E "s|^([[:space:]]*event_initiator_pubkey:).*|\1 \"${PUBLIC_KEY}\"|" config.yaml
                fi
            else
                printf '\n%s\n' "event_initiator_pubkey: \"${PUBLIC_KEY}\"" >> config.yaml
            fi
            echo "✅ Successfully updated config.yaml"
        else
            echo "❌ Error: config.yaml not found. Please create it first."
        fi
    else
        echo "❌ Error: Could not extract public key from event_initiator.identity.json"
    fi
else
    echo "❌ Error: event_initiator.identity.json not found"
fi

echo "✨ Event Initiator setup complete!" 
