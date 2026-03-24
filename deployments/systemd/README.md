# mpcinfra Production Deployment Guide

⚠️ **PRODUCTION DEPLOYMENT ONLY**

This directory contains deployment scripts and configurations for **production deployment** of mpcinfra MPC (Multi-Party Computation) nodes using systemd.

**For local development and testing**, please refer to [INSTALLATION.md](../../INSTALLATION.md) instead.

## Overview

mpcinfra is a distributed threshold cryptographic system that requires multiple nodes to collaborate for secure operations. This deployment guide covers setting up a **secure, production-ready** MPC cluster with proper security hardening, systemd integration, and operational best practices.

## Prerequisites

### Infrastructure Requirements

- **Minimum 3 nodes** (cloud-based, ARM architecture preferred)
- **Linux** distribution
- **Network connectivity** between all nodes
- **External services**: NATS message broker, Consul service discovery

### Software Dependencies

- **Go 1.25+** on all nodes
- **Git** for source code management
- **NATS server** with credentials
- **Consul** for service discovery
- **mkcert** for TLS certificate generation

### Deployment

Follow these steps for manual deployment across your cluster:

#### Step 1: Install Go

Before installing mpcinfra, you need Go 1.25+ installed on all nodes.

**Download Go Binaries with wget:**

For amd64 (x86_64):

```bash
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
```

For arm64 (AArch64, e.g. Graviton or Apple M1/M2 Linux VMs):

```bash
wget https://go.dev/dl/go1.25.0.linux-arm64.tar.gz
```

**Extract to /usr/local:**

Remove any old Go installation first:

```bash
sudo rm -rf /usr/local/go
```

Extract the archive:

```bash
# For amd64
sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz

# For arm64
sudo tar -C /usr/local -xzf go1.25.0.linux-arm64.tar.gz
```

**Update PATH:**

Add Go binary to your environment. Edit `~/.bashrc` or `~/.zshrc`:

```bash
export PATH=$PATH:/usr/local/go/bin
```

Reload shell:

```bash
source ~/.bashrc
```

**Verify Installation:**

```bash
go version
```

You should see:

```
go version go1.25.0 linux/amd64
```

or

```
go version go1.25.0 linux/arm64
```

#### Step 2: Prepare Environment

```bash
# Install mpcinfra binaries (preserve environment to access Go)
sudo -E make install

# Create system user and directories
sudo useradd -r -s /bin/false -d /opt/mpcinfra -c "mpcinfra MPC Node" mpcinfra
sudo mkdir -p /opt/mpcinfra /etc/mpcinfra
```

#### Step 3: Configure Permissions

```bash
# Application data directories (service-owned)
sudo chown -R mpcinfra:mpcinfra /opt/mpcinfra
sudo chmod g+s /opt/mpcinfra
sudo chmod 750 /opt/mpcinfra

# Configuration directory (root-controlled, service-readable)
sudo chown root:mpcinfra /etc/mpcinfra
sudo chmod 750 /etc/mpcinfra
```

#### Step 4: Generate Peer Configuration

On **one designated node** only:

```bash
cd /opt/mpcinfra
mpcinfra-cli generate-peers -n 3
```

#### Step 5: Copy Config and Update Configuration

```bash
# Copy configuration template
cp ~/mpcinfra/config.prod.yaml.template /etc/mpcinfra/config.yaml
# Set proper configuration permissions
sudo chown root:mpcinfra /etc/mpcinfra/config.yaml
sudo chmod 640 /etc/mpcinfra/config.yaml
```

Edit `/etc/mpcinfra/config.yaml` to include:

- NATS server connection details and credentials
- Consul service discovery configuration
- MPC threshold settings (`mpc_threshold`)
- Event initiator public key (will be updated in Step 5)

#### Step 6: Generate Event Initiator Key

On **one designated node** only:

```bash
mpcinfra-cli generate-initiator --encrypt
```

⚠️ **Important**:

- This creates an encrypted private key file with `.key.age` extension that you'll need to securely distribute to application nodes that initiate MPC operations
- Copy the public key from `initiator_identity.json` and update the `event_initiator_pubkey` field in `/etc/mpcinfra/config.yaml` on **all nodes**

#### Step 7: Configure Each Node

```bash
# Register peers
mpcinfra-cli register-peers --config /etc/mpcinfra/config.yaml --environment production

# Generate node identity (with encryption) - replace node0 with actual node name
mpcinfra-cli generate-identity --node node0 --encrypt
```

#### Step 8: Generate TLS Certificates

#### Step 9: Configure Database Encryption

```bash
cd ~/mpcinfra/deployments
./setup-mpcinfra-cred.sh
# Enter BadgerDB password when prompted
# ⚠️ IMPORTANT: Backup password to secure storage (e.g., Bitwarden)
```

#### Step 10: Deploy Service

```bash
sudo ./setup-config.sh
```

#### Step 11: Verify Deployment

```bash
# Check service status
sudo systemctl status mpcinfra

# Monitor logs
journalctl -f -u mpcinfra
```

## Directory Structure

After deployment, the following directory structure is created:

```
/opt/mpcinfra/           # Application home (mpcinfra:mpcinfra, 750)
├── certs/             # TLS certificates
│   ├── client-cert.pem
│   ├── client-key.pem
│   └── rootCA.pem
├── db/                # BadgerDB storage (auto-created)
├── backups/           # Encrypted backups (auto-created)
├── identity/          # Node identity files (auto-created)
│   ├── node0_identity.json
│   ├── node1_identity.json
│   ├── node2_identity.json
│   └── node{X}_private.key  # Current node's private key
├── peers.json         # Peer registry
└── .env               # Environment variables

/etc/mpcinfra/           # Configuration (root:mpcinfra, 750)
└── config.yaml        # Main configuration (root:mpcinfra, 640)
```

### Identity Directory Examples

**Node 0 (unencrypted private key):**
```
/opt/mpcinfra/identity/
├── node0_identity.json
├── node0_private.key      # This node's private key
├── node1_identity.json
└── node2_identity.json
```
*Generated with:* `mpcinfra-cli generate-identity --node node0 --config /etc/mpcinfra/config.yaml`

**Node 1 (encrypted private key):**
```
/opt/mpcinfra/identity/
├── node0_identity.json
├── node1_identity.json
├── node1_private.key.age  # This node's encrypted private key
└── node2_identity.json
```
*Generated with:* `mpcinfra-cli generate-identity --node node1 --config /etc/mpcinfra/config.yaml --encrypt`

## Security Considerations

### File Permissions

- Configuration files are **root-controlled** to prevent tampering
- Application data is **service-owned** for runtime access
- Database encryption is **mandatory** in production

### Network Security

- All inter-node communication uses **Ed25519 signatures**
- Message payloads encrypted with **ECDH key exchange**
- TLS required for NATS connections

### Systemd Security

The service runs with enhanced security:

- **Non-privileged user** (`mpcinfra`)
- **Read-only** configuration directory
- **Private temp** directory
- **System call filtering**
- **Capability restrictions**

## Monitoring and Maintenance

### Service Management

```bash
# Service status
sudo systemctl status mpcinfra

# Start/stop/restart
sudo systemctl start mpcinfra
sudo systemctl stop mpcinfra
sudo systemctl restart mpcinfra

# View logs
journalctl -u mpcinfra
journalctl -f -u mpcinfra  # Follow logs
```

### Health Checks

The deployment includes Consul-based health monitoring. Check cluster health via your Consul UI.

### Backup Management

BadgerDB automatically creates encrypted backups in `/opt/mpcinfra/backups/`. Ensure regular backup of:

- Database encryption password
- Node identity files
- Configuration files

## Troubleshooting

### Common Issues

**Service won't start:**

```bash
# Check service logs
journalctl -u mpcinfra --no-pager

# Verify configuration
sudo ./setup-config.sh verify
```

**Network connectivity:**

- Verify NATS and Consul connectivity
- Check firewall rules between nodes
- Validate TLS certificates

### Log Analysis

Service logs are available via systemd journal:

```bash
# Recent logs
journalctl -u mpcinfra -n 100

# Logs since specific time
journalctl -u mpcinfra --since "1 hour ago"

# Filter by log level
journalctl -u mpcinfra -p err
```
