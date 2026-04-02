# E2E Testing for mpcinfra

This directory contains end-to-end integration tests for the mpcinfra multi-party computation system.

## Overview

The E2E tests verify that the complete MPC system works correctly by:

1. **Infrastructure Setup**: Docker Compose to spin up isolated NATS and Consul instances
2. **Node Setup**: Creating 3 test nodes with separate identities and configurations
3. **Key Generation**: FROST DKG (Ed25519) + DKLS19 pair setup (secp256k1)
4. **Signing**: DKLS19 pairwise ECDSA signing and FROST threshold EdDSA signing
5. **Resharing**: DKLS19 key refresh and FROST proactive re-sharing
6. **Cleanup**: Removing all test artifacts and containers

## Cryptographic Protocols

### ECDSA (secp256k1) - Bitcoin, Ethereum

- **Key Generation**: FROST-style group DKG on secp256k1, then DKLS19 pairwise OT setup
- **Signing**: DKLS19 2-party threshold signing (Alice/Bob pairs)
- **Resharing**: DKLS19 key refresh

### EdDSA (Ed25519) - Solana

- **Key Generation**: FROST DKG
- **Signing**: FROST threshold signing
- **Resharing**: FROST proactive re-sharing

### Library

All MPC protocols use `github.com/keyzon-technologies/kryptology v1.0.2`.

## Prerequisites

Before running the tests, ensure you have:

- **Docker** installed and running
- **Go** 1.23+ installed
- **mpcinfra** and **mpcinfra-cli** binaries built (run `make` in the root directory)

## Running Tests

### Quick Start

```bash
# Run all E2E tests
make test

# Clean up test artifacts
make clean
```

### Manual Steps

1. **Build the binaries** (from root directory):

   ```bash
   make
   ```

2. **Run the E2E tests**:
   ```bash
   cd e2e
   make test
   ```

## Test Structure

### Files

- `base_test.go` - Core test infrastructure, suite setup, cleanup, DB verification
- `keygen_test.go` - Key generation tests (FROST DKG + DKLS19 pair setup)
- `sign_test.go` - Signing tests (ECDSA via DKLS19, EdDSA via FROST)
- `sign_ckd_test.go` - Signing with HD wallet child key derivation (BIP-44)
- `reshare_test.go` - Key resharing tests (DKLS19 refresh, FROST re-share)
- `docker-compose.test.yaml` - Test infrastructure (NATS, Consul)
- `config.test.yaml.template` - Test node configuration template
- `setup_test_identities.sh` - Script to set up test node identities
- `cleanup_test_env.sh` - Standalone cleanup script
- `Makefile` - Build and test automation

### Test Flow

1. **Setup Infrastructure**

   - Starts NATS (port 4223) and Consul (port 8501) containers
   - Creates service clients for test coordination

2. **Setup Test Nodes**

   - Creates 3 test nodes (`test_node0`, `test_node1`, `test_node2`)
   - Generates unique identities for each node
   - Configures separate database paths (`./test_db/`)
   - Registers peers in Consul

3. **Start MPC Nodes**

   - Launches 3 mpcinfra processes in parallel
   - Each node uses its own configuration and identity

4. **Test Key Generation**

   - Generates random wallet IDs
   - Triggers key generation via NATS (runs FROST DKG + DKLS19 setup)
   - Waits for completion (15 minute timeout)

5. **Test Signing**

   - ECDSA: sends transactions via DKLS19 pairwise signing, validates R/S/V components using kryptology secp256k1 curve
   - EdDSA: sends transactions via FROST signing, validates 64-byte signatures

6. **Test Resharing**

   - Triggers key refresh with new threshold/node set
   - Verifies signing still works with reshared keys

7. **Cleanup**
   - Stops all processes
   - Removes Docker containers
   - Deletes test databases and temporary files

## Configuration

### Test Ports

The tests use different ports to avoid conflicts with running services:

- **NATS**: 4223 (vs 4222 for main)
- **Consul**: 8501 (vs 8500 for main)

### Database Path

Test nodes use a separate database path: `./test_db/` instead of `./db/`

## Troubleshooting

### Common Issues

1. **Binary not found**

   ```
   mpcinfra binary not found in PATH
   ```

   **Solution**: Run `make` in the root directory to build the binaries.

2. **Port conflicts**

   ```
   Error: port 4223 already in use
   ```

   **Solution**: Run `make clean` to stop any existing test containers.

3. **Permission errors**
   ```
   Error: cannot create test_db directory
   ```
   **Solution**: Ensure you have write permissions in the e2e directory.

### Debugging

To debug test failures:

1. **Check container logs**:

   ```bash
   docker logs nats-server-test
   docker logs consul-test
   ```

2. **Run with verbose output**:

   ```bash
   go test -v -timeout=10m ./...
   ```

3. **Keep test artifacts** (comment out cleanup in the test):
   ```bash
   ls -la test_db/
   cat test_node0/config.yaml
   ```

## Test Cleanup and Process Management

### Automatic Cleanup

- **Pre-test cleanup**: Every test run starts with `CleanupTestEnvironment()` which kills existing MPC processes, stops Docker containers, and removes test artifacts
- **Post-test cleanup**: Tests use `defer` to ensure cleanup happens even if tests fail

### Manual Cleanup

```bash
# Option 1: Use the cleanup script
cd e2e && ./cleanup_test_env.sh

# Option 2: Use the Makefile target
make clean

# Option 3: Manual cleanup
pkill -f mpcinfra
docker compose -f docker-compose.test.yaml down -v --remove-orphans
rm -rf test_node* logs
```

### Common Issues and Solutions

| Issue                                | Cause                           | Solution                        |
| ------------------------------------ | ------------------------------- | ------------------------------- |
| "Failed to verify initiator message" | Multiple MPC instances running  | Run cleanup script              |
| "Port already in use"                | Docker containers still running | `docker compose down -v`        |
| "Database locked"                    | Previous test didn't clean up   | Remove `test_node*` directories |
| Test hangs during setup              | Leftover processes interfering  | Kill all `mpcinfra` processes   |

## Integration with CI/CD

```yaml
# Example GitHub Actions step
- name: Run E2E Tests
  run: |
    make
    cd e2e
    make test
```
