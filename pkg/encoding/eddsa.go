package encoding

import (
	"crypto/ed25519"
	"fmt"
)

// EncodeEDDSAPubKey returns the raw 32-byte Ed25519 public key.
func EncodeEDDSAPubKey(pubKey ed25519.PublicKey) ([]byte, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: want %d, got %d", ed25519.PublicKeySize, len(pubKey))
	}
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, pubKey)
	return out, nil
}

// DecodeEDDSAPubKey parses 32 raw bytes into a standard crypto/ed25519.PublicKey.
func DecodeEDDSAPubKey(encodedKey []byte) (ed25519.PublicKey, error) {
	if len(encodedKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid EdDSA public key length: want %d, got %d", ed25519.PublicKeySize, len(encodedKey))
	}
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, encodedKey)
	return ed25519.PublicKey(out), nil
}
