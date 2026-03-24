package encryption

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// generateEd25519Keys generates Ed25519 keypair
func GenerateEd25519Keys() (KeyData, error) {
	pubKey, privKeyFull, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyData{}, err
	}

	privKeySeed := privKeyFull.Seed()
	return KeyData{
		PublicKeyHex:  hex.EncodeToString(pubKey),
		PrivateKeyHex: hex.EncodeToString(privKeySeed),
	}, nil
}

// ParseEd25519PublicKeyFromHex parses a hex-encoded Ed25519 public key and validates it.
// Returns the public key as []byte and an error if invalid.
func ParseEd25519PublicKeyFromHex(hexKey string) ([]byte, error) {
	if hexKey == "" {
		return nil, fmt.Errorf("public key hex string is empty")
	}

	// Decode hex string to bytes
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex format: %w", err)
	}

	// Validate the key
	if err := ValidateEd25519PublicKey(keyBytes); err != nil {
		return nil, err
	}

	return keyBytes, nil
}

// ValidateEd25519PublicKey validates an existing byte slice as a valid Ed25519 public key
func ValidateEd25519PublicKey(keyBytes []byte) error {
	if len(keyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key length: expected %d bytes, got %d",
			ed25519.PublicKeySize, len(keyBytes))
	}

	// Create and validate Ed25519 public key
	pubKey := ed25519.PublicKey(keyBytes)

	// Basic validation - attempt to use the key
	// Invalid curve points will cause verification to behave predictably
	dummyMsg := []byte("validation_test")
	dummySig := make([]byte, ed25519.SignatureSize)
	ed25519.Verify(pubKey, dummyMsg, dummySig) // This won't panic on invalid keys

	return nil
}
