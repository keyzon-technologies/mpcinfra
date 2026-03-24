package mpc

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
)

const chainCodeLength = 32

var (
	ErrInvalidChainCode = errors.New("invalid chain code length")
	ErrNilKey           = errors.New("key cannot be nil")
	ErrNilPoint         = errors.New("point cannot be nil")
)

// CKD handles Child Key Derivation (BIP32-style, curve-agnostic).
type CKD struct {
	masterChainCode []byte
}

// NewCKDFromHex creates a CKD from a hex-encoded 32-byte chain code string.
func NewCKDFromHex(hexStr string) (*CKD, error) {
	if hexStr == "" {
		return nil, fmt.Errorf("chain code is empty")
	}
	code, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid chain code hex: %w", err)
	}
	if len(code) != chainCodeLength {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidChainCode, len(code), chainCodeLength)
	}
	return &CKD{masterChainCode: code}, nil
}

// GetMasterChainCode returns a copy of the chain code.
func (c *CKD) GetMasterChainCode() []byte {
	out := make([]byte, len(c.masterChainCode))
	copy(out, c.masterChainCode)
	return out
}

// DeriveForCurve derives a BIP32-style child scalar tweak and child public key
// from the given public key bytes and derivation path, using the kryptology
// curves.Scalar / curves.Point types.
//
// pubKeyBytes may be:
//   - 32 bytes  → Ed25519 compressed point
//   - 33 bytes  → secp256k1 compressed point
//   - 64 bytes  → uncompressed X‖Y (secp256k1 stored without 0x04 prefix)
//   - 65 bytes  → uncompressed 0x04‖X‖Y (secp256k1)
//
// Returns (totalTweak, childPublicKey, error).
// For ECDSA (secp256k1): only Alice adds the tweak to her signing share.
// For EdDSA (Ed25519):   only the signer with participant ID 1 adds the tweak.
func (c *CKD) DeriveForCurve(walletID string, pubKeyBytes []byte, path []uint32, curve *curves.Curve) (curves.Scalar, curves.Point, error) {
	if curve == nil {
		return nil, nil, errors.New("DeriveForCurve: curve cannot be nil")
	}

	// Parse the starting public key.
	startPoint, err := parsePoint(pubKeyBytes, curve)
	if err != nil {
		return nil, nil, fmt.Errorf("DeriveForCurve: parse public key: %w", err)
	}

	chainCode := make([]byte, len(c.masterChainCode))
	copy(chainCode, c.masterChainCode)

	totalTweak := curve.NewScalar() // accumulates IL scalars
	currentPoint := startPoint

	for _, index := range path {
		// Use the current (child) public key's compressed bytes as the key-material.
		pubCompressed := currentPoint.ToAffineCompressed()

		mac := hmac.New(sha512.New, chainCode)
		mac.Write(pubCompressed)

		var indexBuf [4]byte
		binary.BigEndian.PutUint32(indexBuf[:], index)
		mac.Write(indexBuf[:])

		h := mac.Sum(nil) // 64 bytes
		il := h[:32]      // additive tweak
		ir := h[32:]      // next chain code

		// Reduce IL mod group order via SetBigInt, since the raw 32-byte
		// HMAC output may exceed the group order.
		ilScalar, err := curve.Scalar.SetBigInt(new(big.Int).SetBytes(il))
		if err != nil {
			return nil, nil, fmt.Errorf("DeriveForCurve: IL scalar at index %d: %w", index, err)
		}

		totalTweak = totalTweak.Add(ilScalar)
		currentPoint = currentPoint.Add(curve.ScalarBaseMult(ilScalar))
		chainCode = ir
	}

	return totalTweak, currentPoint, nil
}

// parsePoint decodes a public key from bytes, supporting compressed and
// uncompressed formats for both secp256k1 and Ed25519.
func parsePoint(b []byte, curve *curves.Curve) (curves.Point, error) {
	switch len(b) {
	case 32, 33:
		// Ed25519 compressed (32) or secp256k1 compressed (33).
		return curve.Point.FromAffineCompressed(b)
	case 64:
		// Uncompressed X‖Y without 0x04 prefix. Try with prefix for secp256k1;
		// for Ed25519 this length doesn't arise in practice.
		pt, err := curve.Point.FromAffineUncompressed(append([]byte{0x04}, b...))
		if err != nil {
			// Fall back: try raw 64-byte uncompressed (some curves omit prefix).
			pt, err = curve.Point.FromAffineUncompressed(b)
		}
		return pt, err
	case 65:
		return curve.Point.FromAffineUncompressed(b)
	default:
		return nil, fmt.Errorf("unsupported public key length %d", len(b))
	}
}
