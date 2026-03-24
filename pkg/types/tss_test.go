package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshalMpcMsg(t *testing.T) {
	original := &MpcMsg{
		WalletID:   "wallet-123",
		Protocol:   ProtoDklsSign,
		Round:      "round-1",
		FromNodeID: "node-a",
		ToNodeID:   "node-b",
		Payload:    []byte("test payload"),
		Signature:  []byte("test-sig"),
	}

	b, err := MarshalMpcMsg(original)
	require.NoError(t, err)
	assert.NotEmpty(t, b)

	got, err := UnmarshalMpcMsg(b)
	require.NoError(t, err)
	assert.Equal(t, original.WalletID, got.WalletID)
	assert.Equal(t, original.Protocol, got.Protocol)
	assert.Equal(t, original.Round, got.Round)
	assert.Equal(t, original.FromNodeID, got.FromNodeID)
	assert.Equal(t, original.ToNodeID, got.ToNodeID)
	assert.Equal(t, original.Payload, got.Payload)
	assert.Equal(t, original.Signature, got.Signature)
}

func TestMpcMsg_MarshalForSigning_ExcludesSig(t *testing.T) {
	msg := &MpcMsg{
		WalletID:   "wallet-abc",
		Protocol:   ProtoFrostSign,
		Round:      "r1",
		FromNodeID: "node-1",
		Payload:    []byte("data"),
		Signature:  []byte("should-be-excluded"),
	}

	b1, err := msg.MarshalForSigning()
	require.NoError(t, err)
	assert.NotEmpty(t, b1)

	// Changing signature must not change signing bytes.
	msg.Signature = []byte("other-sig")
	b2, err := msg.MarshalForSigning()
	require.NoError(t, err)
	assert.Equal(t, b1, b2)
}

func TestMpcMsg_MarshalForSigning_Deterministic(t *testing.T) {
	msg := &MpcMsg{
		WalletID:   "w",
		Protocol:   ProtoFrostDKG,
		FromNodeID: "n",
		Payload:    []byte("p"),
	}

	b1, err := msg.MarshalForSigning()
	require.NoError(t, err)
	b2, err := msg.MarshalForSigning()
	require.NoError(t, err)
	assert.Equal(t, b1, b2)
}

func TestMarshalStartMessage_RoundTrip(t *testing.T) {
	params := []byte("start parameters")

	b, err := MarshalStartMessage(params)
	require.NoError(t, err)
	assert.NotEmpty(t, b)

	got, err := UnmarshalStartMessage(b)
	require.NoError(t, err)
	assert.Equal(t, params, got.Params)
}

func TestUnmarshalMpcMsg_InvalidJSON(t *testing.T) {
	_, err := UnmarshalMpcMsg([]byte("invalid json"))
	assert.Error(t, err)
}

func TestUnmarshalStartMessage_InvalidJSON(t *testing.T) {
	_, err := UnmarshalStartMessage([]byte("invalid json"))
	assert.Error(t, err)
}
