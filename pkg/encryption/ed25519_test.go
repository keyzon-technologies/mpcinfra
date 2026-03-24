package encryption

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

var (
	// Test data shared across tests
	testValidKey ed25519.PublicKey
	testValidHex string
	testAllZeros = make([]byte, 32)
	testAllMax   = func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = 0xFF
		}
		return b
	}()
)

func init() {
	// Generate a single valid key for all tests
	testValidKey, _, _ = ed25519.GenerateKey(rand.Reader)
	testValidHex = hex.EncodeToString(testValidKey)
}

// Helper function to check error expectations
func checkError(t *testing.T, err error, wantError bool, errorMsg string) {
	t.Helper()
	if wantError {
		if err == nil {
			t.Errorf("expected error but got none")
		} else if errorMsg != "" && !strings.Contains(err.Error(), errorMsg) {
			t.Errorf("error = %v, want error containing %v", err, errorMsg)
		}
	} else if err != nil {
		t.Errorf("unexpected error = %v", err)
	}
}

func TestParseEd25519PublicKeyFromHex(t *testing.T) {
	tests := []struct {
		name      string
		hexKey    string
		wantError bool
		errorMsg  string
	}{
		{"valid hex key", testValidHex, false, ""},
		{"empty hex string", "", true, "public key hex string is empty"},
		{"invalid hex characters", strings.Repeat("g", 64), true, "invalid hex format"},
		{"too short hex string", "abcdef1234567890", true, "invalid Ed25519 public key length: expected 32 bytes, got 8"},
		{"too long hex string", strings.Repeat("ab", 40), true, "invalid Ed25519 public key length: expected 32 bytes, got 40"},
		{"odd length hex string", "abc", true, "invalid hex format"},
		{"all zeros", hex.EncodeToString(testAllZeros), false, ""},
		{"all max bytes", hex.EncodeToString(testAllMax), false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseEd25519PublicKeyFromHex(tt.hexKey)

			checkError(t, err, tt.wantError, tt.errorMsg)

			if !tt.wantError {
				if result == nil {
					t.Errorf("expected non-nil result")
				} else if len(result) != ed25519.PublicKeySize {
					t.Errorf("result length = %d, want %d", len(result), ed25519.PublicKeySize)
				}
			} else if result != nil {
				t.Errorf("expected nil result on error, got %v", result)
			}
		})
	}
}

func TestValidateEd25519PublicKey(t *testing.T) {
	tests := []struct {
		name      string
		keyBytes  []byte
		wantError bool
		errorMsg  string
	}{
		{"valid public key", testValidKey, false, ""},
		{"nil key bytes", nil, true, "invalid Ed25519 public key length: expected 32 bytes, got 0"},
		{"empty key bytes", []byte{}, true, "invalid Ed25519 public key length: expected 32 bytes, got 0"},
		{"too short key", make([]byte, 16), true, "invalid Ed25519 public key length: expected 32 bytes, got 16"},
		{"too long key", make([]byte, 64), true, "invalid Ed25519 public key length: expected 32 bytes, got 64"},
		{"all zeros", testAllZeros, false, ""},
		{"all max bytes", testAllMax, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEd25519PublicKey(tt.keyBytes)
			checkError(t, err, tt.wantError, tt.errorMsg)
		})
	}
}

func TestParseAndValidateIntegration(t *testing.T) {
	testKeys := []ed25519.PublicKey{testValidKey}

	// Generate a few more keys for testing
	for i := 0; i < 3; i++ {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate test key %d: %v", i, err)
		}
		testKeys = append(testKeys, pubKey)
	}

	for i, validPubKey := range testKeys {
		validHex := hex.EncodeToString(validPubKey)

		parsedKey, err := ParseEd25519PublicKeyFromHex(validHex)
		if err != nil {
			t.Errorf("ParseEd25519PublicKeyFromHex() failed for key %d: %v", i, err)
			continue
		}

		if err := ValidateEd25519PublicKey(parsedKey); err != nil {
			t.Errorf("ValidateEd25519PublicKey() failed for key %d: %v", i, err)
		}

		if !compareBytes(validPubKey, parsedKey) {
			t.Errorf("Key %d: parsed key differs from original", i)
		}
	}
}

// Helper function to compare byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func BenchmarkParseEd25519PublicKeyFromHex(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParseEd25519PublicKeyFromHex(testValidHex)
	}
}

func BenchmarkValidateEd25519PublicKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateEd25519PublicKey(testValidKey)
	}
}
