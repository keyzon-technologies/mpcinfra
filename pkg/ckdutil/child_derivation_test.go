package ckdutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func validEd25519PubKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return []byte(pub)
}

func TestDeriveEd25519ChildCompressed_Deterministic(t *testing.T) {
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(i + 1)
	}
	chainCodeHex := hex.EncodeToString(chainCode)
	masterPubKey := validEd25519PubKey(t)

	path := []uint32{44, 501, 0, 0}

	child1, err := DeriveEd25519ChildCompressed(masterPubKey, chainCodeHex, path)
	require.NoError(t, err)
	require.Len(t, child1, 32)

	child2, err := DeriveEd25519ChildCompressed(masterPubKey, chainCodeHex, path)
	require.NoError(t, err)
	require.Equal(t, child1, child2, "derivation must be deterministic")
}

func TestDeriveEd25519ChildCompressed_DifferentPaths(t *testing.T) {
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(i + 1)
	}
	chainCodeHex := hex.EncodeToString(chainCode)
	masterPubKey := validEd25519PubKey(t)

	var prev []byte
	for i := uint32(0); i < 10; i++ {
		path := []uint32{44, 501, i, 0}
		child, err := DeriveEd25519ChildCompressed(masterPubKey, chainCodeHex, path)
		require.NoErrorf(t, err, "index %d", i)
		require.Lenf(t, child, 32, "index %d", i)

		if prev != nil {
			require.NotEqualf(t, prev, child, "index %d should differ from %d", i, i-1)
		}
		prev = child
	}
}

func TestDeriveSecp256k1ChildCompressed_Deterministic(t *testing.T) {
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(0xaa - i)
	}
	chainCodeHex := hex.EncodeToString(chainCode)

	curve := btcec.S256()
	masterX, masterY := curve.Params().Gx, curve.Params().Gy
	masterPubBytes := serializeCompressed(masterX, masterY)

	path := []uint32{44, 60, 0, 0, 0}
	child1, err := DeriveSecp256k1ChildCompressed(masterPubBytes, chainCodeHex, path)
	require.NoError(t, err)
	require.Len(t, child1, 33)

	child2, err := DeriveSecp256k1ChildCompressed(masterPubBytes, chainCodeHex, path)
	require.NoError(t, err)
	require.Equal(t, child1, child2, "derivation must be deterministic")
}

func TestDeriveSecp256k1ChildCompressed_DifferentIndices(t *testing.T) {
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = byte(0xaa - i)
	}
	chainCodeHex := hex.EncodeToString(chainCode)

	curve := btcec.S256()
	masterX, masterY := curve.Params().Gx, curve.Params().Gy
	masterPubBytes := serializeCompressed(masterX, masterY)

	var prev []byte
	for i := uint32(0); i < 10; i++ {
		path := []uint32{44, 60, 0, 0, i}
		child, err := DeriveSecp256k1ChildCompressed(masterPubBytes, chainCodeHex, path)
		require.NoErrorf(t, err, "index %d", i)
		require.Lenf(t, child, 33, "index %d", i)

		if prev != nil {
			require.NotEqualf(t, prev, child, "index %d should differ from %d", i, i-1)
		}
		prev = child
	}
}
