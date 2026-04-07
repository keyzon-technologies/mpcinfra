**Keygen Flow – Execution Order**

**1. Request entry**
`cmd/mpcinfra/main.go → runNode()`

Initializes the NATS connection, database, peer registry, and consumers

**2. Request reception**
`pkg/eventconsumer/keygen_consumer.go → handleKeygenEvent()`

Consumes a JetStream message on topic `mpc.keygen_request.*`
Validates the initiator’s signature and authorization
Publishes to the internal topic `mpc:generate`

**3. Event processing**
`pkg/eventconsumer/event_consumer.go → handleKeyGenEvent()`

Verifies the initiator’s signature
Checks for duplicate sessions
Creates two sessions in parallel: ECDSA + EdDSA
Calls `Init()` on both

**4. Session initialization**
`pkg/mpc/session.go → session base`

Subscribes to NATS topics for broadcast and direct messages
Calls `WaitForPeersReady()` — synchronization barrier with all peers via NATS request/reply

**5a. EdDSA protocol (simpler)**
`pkg/mpc/eddsa_keygen_session.go`

FROST DKG Round 1 → broadcast + p2p Shamir shares
FROST DKG Round 2 → broadcast of verification key shares
→ `persistAndFinish()`

**5b. ECDSA protocol (two stages)**
`pkg/mpc/ecdsa_keygen_session.go`

**Phase 1 – FROST DKG:**
Round 1 → broadcast + p2p Shamir shares for each peer
Round 2 → broadcast of verification key shares

**Phase 2 – DKLS19 Pair Setup (9 rounds per node pair):**
Rounds 1–9 per Alice/Bob pair
└─ Commitment, Schnorr proof, Oblivious Transfer (OT)
→ `persistAndFinish()`

**6. Persistence and result**
`pkg/mpc/ecdsa_keygen_session.go → persistAndFinish()`

Saves `ECDSAKeygenData` and `EDDSAKeygenData` in BadgerDB
Saves `KeyInfo` (participants, threshold) in Consul
Publishes result to `mpc.mpc_keygen_result.{walletID}` with ECDSA and EdDSA public keys

---

## Summary Diagram

```
GenerateKeyMessage (JetStream)
    ↓
keygen_consumer.go → verify and forward
    ↓
event_consumer.go → creates 2 sessions (ECDSA + EdDSA)
    ↓
session.go → WaitForPeersReady() (synchronization)
    ↓
   ECDSA                          EdDSA
   ecdsa_keygen_session.go        eddsa_keygen_session.go
   ├─ FROST DKG R1+R2             └─ FROST DKG R1+R2
   └─ DKLS19 Pairs R1→R9              ↓ persistAndFinish()
        ↓ persistAndFinish()
    ↓
BadgerDB + Consul + publish result
```

**Inter-node communication**
Broadcast → topic `keygen:broadcast:{ecdsa|eddsa}:{walletID}` (signed with Ed25519)
Direct (P2P) → topic `keygen:direct:{ecdsa|eddsa}:{fromID}:{toID}:{walletID}` (encrypted with ECDH)

**Transport** → `pkg/messaging/point2point.go` and `pkg/messaging/pubsub.go`
