## Running NATS and Consul (Development Only)

> ⚠️ This setup is insecure and should only be used for development. For production, use a secure cluster environment with TLS certificates.

### Docker Compose Configuration

Create a `docker-compose.yaml` file:

```yaml
version: "3"

services:
  nats-server:
    image: nats:latest
    container_name: nats-server
    command: -js --http_port 8222
    ports:
      - "4222:4222"
      - "8222:8222"
      - "6222:6222"
    tty: true
    restart: always

  consul:
    image: consul:1.15.4
    container_name: consul
    ports:
      - "8500:8500"
      - "8601:8600/udp"
    command: "agent -server -ui -node=server-1 -bootstrap-expect=1 -client=0.0.0.0"
    restart: always
```

### Start the Services

```bash
docker compose up -d
```

---

## Generate Peer Configuration

```bash
mpcinfra-cli generate-peers -n 3
```

Example output:

```json
{
  "node0": "12345678-1234-1234-1234-123456789abc",
  "node1": "23456789-2345-2345-2345-23456789abcd",
  "node2": "34567890-3456-3456-3456-3456789abcde"
}
```

---

## Cluster Configuration

### 1. Create and Update `config.yaml`

```bash
cp config.yaml.template config.yaml
```

Edit `config.yaml`:

```yaml
nats:
  url: nats://127.0.0.1:4222
consul:
  address: localhost:8500

mpc_threshold: 2
environment: development
badger_password: "your_badger_password"
event_initiator_pubkey: "your_event_initiator_pubkey"
```

### Generate a Strong Password (Recommended)

```bash
< /dev/urandom tr -dc 'A-Za-z0-9!@#$^&*()-_=+[]{}|;:,.<>?/~' | head -c 16; echo
```

Example:

```yaml
badger_password: "F))ysJp?E]ol&I;^"
```

### 2. Register Peers to Consul

```bash
mpcinfra-cli register-peers
```

---

## Event Initiator Setup

### Generate the Initiator

```bash
mpcinfra-cli generate-initiator
```

> 💡 Use `--encrypt` in production.

### Add Public Key to `config.yaml`

From `event_initiator.identity.json`:

```json
{
  "public_key": "09be5d070816aadaa1b6638cad33e819a8aed7101626f6bf1e0b427412c3408a"
}
```

Update `config.yaml`:

```yaml
event_initiator_pubkey: "09be5d070816aadaa1b6638cad33e819a8aed7101626f6bf1e0b427412c3408a"
```

---

## Configure Node Identities

### 1. Create Node Folders

```bash
mkdir node{0..2}
for dir in node{0..2}; do
  cp config.yaml peers.json "$dir/"
  mkdir -p "$dir/identity"
done
```

### 2. Generate Identity for Each Node

Example for `node0`:

```bash
cd node0
mpcinfra-cli generate-identity --node node0
```

> 💡 For production, use encryption:
>
> ```bash
> mpcinfra-cli generate-identity --node node0 --encrypt
> ```

### Generate Strong Password for Encryption

```bash
< /dev/urandom tr -dc 'A-Za-z0-9!@#$^&*()-_=+[]{}|;:,.<>?/~' | head -c 16; echo
```

### 3. Distribute Identity Files to All Nodes

```bash
cp identity/node0_identity.json ../node1/identity/node0_identity.json
cp identity/node0_identity.json ../node2/identity/node0_identity.json
```

Repeat this for `node1` and `node2`.

### Folder Structure Example

```
├── node0
│   ├── config.yaml
│   ├── identity
│   │   ├── node0_identity.json
│   │   ├── node0_private.key
│   │   ├── node1_identity.json
│   │   └── node2_identity.json
│   └── peers.json
├── node1
│   ├── config.yaml
│   ├── identity
│   │   ├── node0_identity.json
│   │   ├── node1_identity.json
│   │   ├── node1_private.key
│   │   └── node2_identity.json
│   └── peers.json
├── node2
│   ├── config.yaml
│   ├── identity
│   │   ├── node0_identity.json
│   │   ├── node1_identity.json
│   │   ├── node2_identity.json
│   │   └── node2_private.key
│   └── peers.json
```

---

## Start mpcinfra Nodes

Start each node:

```bash
cd node0
mpcinfra start -n node0
```

```bash
cd node1
mpcinfra start -n node1
```

```bash
cd node2
mpcinfra start -n node2
```

> 💡 In production, avoid hardcoded passwords:
>
> ```bash
> mpcinfra start -n node0 --prompt-credentials
> ```
