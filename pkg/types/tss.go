package types

import "encoding/json"

// ─── Generic envelope ────────────────────────────────────────────────────────

// MpcMsg is the outer envelope used for all MPC protocol messages transported
// over NATS (both broadcast and point-to-point).  It replaces the old TssMessage
// that carried tss.PartyID values; node identity is now represented as plain
// strings, matching the node IDs used in Consul and the peer registry.
type MpcMsg struct {
	// WalletID identifies the keygen/sign session.
	WalletID string `json:"walletID"`

	// Protocol identifies which sub-protocol produced this message.
	// Valid values: "dkls-group-dkg", "dkls-pair-setup", "dkls-sign",
	//               "frost-dkg", "frost-sign", "dkls-refresh", "frost-reshare".
	Protocol string `json:"protocol"`

	// Round is a human-readable round label for logging (e.g. "dkg-round-1").
	Round string `json:"round,omitempty"`

	// PairAlice and PairBob identify the Alice/Bob pair for DKLS19 messages.
	// For FROST messages these fields are empty.
	PairAlice string `json:"pairAlice,omitempty"`
	PairBob   string `json:"pairBob,omitempty"`

	// FromNodeID is the sender's node ID.
	FromNodeID string `json:"from"`

	// ToNodeID is the intended recipient's node ID.
	// Empty for broadcast messages (FROST DKG Round1Bcast, etc.).
	ToNodeID string `json:"to,omitempty"`

	// Payload carries the gob-encoded protocol.Message produced by the kryptology
	// iterator (AliceDkg.Next / BobDkg.Next / etc.).
	Payload []byte `json:"payload"`

	// Signature is the Ed25519 signature over MarshalForSigning().
	// Set only on broadcast messages (point-to-point messages are AEAD-encrypted
	// and authenticated by the encryption layer instead).
	Signature []byte `json:"sig,omitempty"`
}

// MarshalMpcMsg serialises msg to JSON.
func MarshalMpcMsg(msg *MpcMsg) ([]byte, error) {
	return json.Marshal(msg)
}

// UnmarshalMpcMsg deserialises JSON bytes into an MpcMsg.
func UnmarshalMpcMsg(b []byte) (*MpcMsg, error) {
	msg := &MpcMsg{}
	return msg, json.Unmarshal(b, msg)
}

// MarshalForSigning returns the canonical JSON bytes that are signed/verified
// for broadcast MpcMsg messages.  The Signature field is excluded.
func (m *MpcMsg) MarshalForSigning() ([]byte, error) {
	type signingView struct {
		WalletID   string `json:"walletID"`
		Protocol   string `json:"protocol"`
		Round      string `json:"round,omitempty"`
		PairAlice  string `json:"pairAlice,omitempty"`
		PairBob    string `json:"pairBob,omitempty"`
		FromNodeID string `json:"from"`
		ToNodeID   string `json:"to,omitempty"`
		Payload    []byte `json:"payload"`
	}
	return json.Marshal(signingView{
		WalletID:   m.WalletID,
		Protocol:   m.Protocol,
		Round:      m.Round,
		PairAlice:  m.PairAlice,
		PairBob:    m.PairBob,
		FromNodeID: m.FromNodeID,
		ToNodeID:   m.ToNodeID,
		Payload:    m.Payload,
	})
}

// ─── Protocol constants ───────────────────────────────────────────────────────

const (
	ProtoDklsGroupDKG  = "dkls-group-dkg"  // FROST-style group DKG on secp256k1
	ProtoDklsPairSetup = "dkls-pair-setup"  // DKLS19 pairwise OT setup
	ProtoDklsSign      = "dkls-sign"        // DKLS19 pairwise signing
	ProtoDklsRefresh   = "dkls-refresh"     // DKLS19 key refresh (resharing)
	ProtoFrostDKG      = "frost-dkg"        // FROST DKG (EdDSA / Ed25519)
	ProtoFrostSign     = "frost-sign"       // FROST signing (EdDSA)
	ProtoFrostReshare  = "frost-reshare"    // FROST proactive re-sharing
)

// ─── Initiator / result messages (unchanged shape, no PartyID) ───────────────

// StartMessage wraps arbitrary params for session initiation (kept for compatibility).
type StartMessage struct {
	Params []byte `json:"params"`
}

func MarshalStartMessage(params []byte) ([]byte, error) {
	return json.Marshal(&StartMessage{Params: params})
}

func UnmarshalStartMessage(msgBytes []byte) (*StartMessage, error) {
	msg := &StartMessage{}
	return msg, json.Unmarshal(msgBytes, msg)
}
