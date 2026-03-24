# mpcinfra Installation Guide

## Prerequisites

Before starting, ensure you have:

- **Go** 1.25.0+ installed: [Install Go here](https://go.dev/doc/install)
- **NATS** server running
- **Consul** server running

---

## Clone and Install mpcinfra

### Clone the Repository

```bash
git clone https://github.com/keyzon-technologies/mpcinfra.git
cd mpcinfra
```

### Build the Project

With Make:

```bash
make
```

Or with Go:

```bash
go install ./cmd/mpcinfra
go install ./cmd/mpcinfra-cli
```

### Available Commands

- `mpcinfra`: Start an mpcinfra node
- `mpcinfra-cli`: CLI utility for peer, identity, and initiator configuration

---

## Setup Instructions

**For detailed step-by-step instructions, see [SETUP.md](SETUP.md).**

### Quick Reference

#### 1. Generate peers.json

First, generate the peers configuration file:

```bash
mpcinfra-cli generate-peers -n 3
```

This creates a `peers.json` file with 3 peer nodes (node0, node1, node2). Adjust `-n` for a different number of nodes.

#### 2. Set up Event Initiator

```bash
./setup_initiator.sh
```

This generates the event initiator identity used to authorize MPC operations.

#### 3. Set up Node Identities

```bash
./setup_identities.sh
```

This script:

- Creates node directories (node0, node1, node2)
- Generates identities for each node
- Distributes identity files across nodes
- Configures chain_code for all nodes

**Note:** This script requires `peers.json` to exist. If you see an error about missing peers.json, run step 1 first.

---

![All node ready](images/all-node-ready.png)

---

## chain_code setup (REQUIRED)

### What is chain_code?

The `chain_code` is a cryptographic parameter used for Hierarchical Deterministic (HD) wallet functionality. It enables mpcinfra to derive child keys from a parent key, allowing you to generate multiple wallet addresses from a single master key.

**Important Requirements:**

- **All nodes in your MPC cluster MUST use the identical chain_code value**
- Must be a 32-byte value represented as a 64-character hexadecimal string
- Should be generated once and stored securely
- Without a valid chain_code, mpcinfra nodes will fail to start

### How to generate and configure

Generate one 32-byte hex chain code and set it in all node configurations:

```bash
# Navigate to your mpcinfra directory
cd /path/to/mpcinfra

# Generate a random 32-byte chain code and save it
CC=$(openssl rand -hex 32) && echo "$CC" > .chain_code

# Apply to main config
sed -i -E "s|^([[:space:]]*chain_code:).*|\1 \"$CC\"|" config.yaml

# Apply to all node configs
for n in node0 node1 node2; do
  sed -i -E "s|^([[:space:]]*chain_code:).*|\1 \"$CC\"|" "$n/config.yaml"
done

# Verify it was set correctly
echo "Chain code configured: $CC"
```

**Example config.yaml entry:**

```yaml
chain_code: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
```

Start nodes normally:

```bash
cd node0 && mpcinfra start -n node0
```

Repeat for `node1` and `node2`. The value must be exactly 64 hex chars (32 bytes).

---

## Production Deployment (High Security)

1. Use production-grade **NATS** and **Consul** clusters.
2. Enable **TLS certificates** on all endpoints.
3. Encrypt all keys:
   ```bash
   mpcinfra-cli generate-initiator --encrypt
   mpcinfra-cli generate-identity --node node0 --encrypt
   ```
4. Use `--prompt-credentials` to securely input Badger passwords (avoid hardcoding in `config.yaml`).

---

## Appendix

### Decrypt initiator private key with age

```
age --decrypt -o event_initiator.key event_initiator.key.age
```
