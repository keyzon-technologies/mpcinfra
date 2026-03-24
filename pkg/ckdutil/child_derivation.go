package ckdutil

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
)

const (
	hardenedKeyStart = 0x80000000
	// Compressed pubkey: 1-byte prefix (02/03) + 32-byte X coordinate.
	pubKeyBytesLenCompressed = 33
	// BIP32 specifies child index serialized as 4-byte big-endian (ser32).
	childIndexBytes           = 4
	pubKeyCompressedEven byte = 0x2
	pubKeyCompressedOdd  byte = 0x3
)

// DeriveEd25519ChildCompressed derives a non-hardened child public key on Ed25519
// and returns the 32-byte compressed key (kryptology ToAffineCompressed format).
func DeriveEd25519ChildCompressed(masterPubKey []byte, chainCodeHex string, path []uint32) ([]byte, error) {
	if len(masterPubKey) == 0 {
		return nil, fmt.Errorf("master public key is empty")
	}
	if len(masterPubKey) != 32 {
		return nil, fmt.Errorf("invalid Ed25519 master public key length: want 32, got %d", len(masterPubKey))
	}

	chainCode, err := hex.DecodeString(chainCodeHex)
	if err != nil {
		return nil, fmt.Errorf("decode chain code: %w", err)
	}
	if len(chainCode) != 32 {
		return nil, fmt.Errorf("invalid chain code length: %d", len(chainCode))
	}

	curve := curves.ED25519()

	currentPoint, err := curve.Point.FromAffineCompressed(masterPubKey)
	if err != nil {
		return nil, fmt.Errorf("parse master public key: %w", err)
	}

	currentChainCode := append([]byte(nil), chainCode...)

	for _, index := range path {
		if index >= hardenedKeyStart {
			return nil, fmt.Errorf("hardened derivation not supported: %d", index)
		}

		pubCompressed := currentPoint.ToAffineCompressed() // 32 bytes

		mac := hmac.New(sha512.New, currentChainCode)
		mac.Write(pubCompressed)

		var indexBuf [4]byte
		binary.BigEndian.PutUint32(indexBuf[:], index)
		mac.Write(indexBuf[:])

		h := mac.Sum(nil)
		il := h[:32]
		ir := h[32:]

		// Reduce IL modulo the Ed25519 group order via SetBigInt, since the raw
		// 32-byte HMAC output may exceed the group order.
		ilBig := new(big.Int).SetBytes(il)
		ilScalar, err := curve.Scalar.SetBigInt(ilBig)
		if err != nil {
			return nil, fmt.Errorf("IL scalar at index %d: %w", index, err)
		}

		currentPoint = currentPoint.Add(curve.ScalarBaseMult(ilScalar))
		currentChainCode = ir
	}

	return currentPoint.ToAffineCompressed(), nil
}

// DeriveSecp256k1ChildCompressed derives a non-hardened child public key on secp256k1 and returns the 33-byte compressed key.
func DeriveSecp256k1ChildCompressed(masterPubKey []byte, chainCodeHex string, path []uint32) ([]byte, error) {
	if len(masterPubKey) != 33 {
		return nil, fmt.Errorf("invalid master pubkey length: %d", len(masterPubKey))
	}

	curve := btcec.S256()
	pubKey, err := btcec.ParsePubKey(masterPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode master pubkey: %w", err)
	}

	chainCode, err := hex.DecodeString(chainCodeHex)
	if err != nil {
		return nil, fmt.Errorf("decode chain code: %w", err)
	}
	if len(chainCode) != 32 {
		return nil, fmt.Errorf("invalid chain code length: %d", len(chainCode))
	}

	currentX := new(big.Int).Set(pubKey.X())
	currentY := new(big.Int).Set(pubKey.Y())
	currentChainCode := append([]byte(nil), chainCode...)

	for _, index := range path {
		if index >= hardenedKeyStart {
			return nil, fmt.Errorf("hardened derivation not supported: %d", index)
		}

		data := make([]byte, pubKeyBytesLenCompressed+childIndexBytes)
		copy(data, serializeCompressed(currentX, currentY))
		binary.BigEndian.PutUint32(data[pubKeyBytesLenCompressed:], index)

		mac := hmac.New(sha512.New, currentChainCode)
		mac.Write(data)
		ilr := mac.Sum(nil)
		il := ilr[:32]
		ir := ilr[32:]

		ilNum := new(big.Int).SetBytes(il)
		if ilNum.Sign() == 0 || ilNum.Cmp(curve.Params().N) >= 0 {
			return nil, fmt.Errorf("invalid IL for index %d", index)
		}

		deltaX, deltaY := curve.ScalarBaseMult(ilNum.Bytes())
		childX, childY := curve.Add(currentX, currentY, deltaX, deltaY)
		if childX == nil || childY == nil || childX.Sign() == 0 || childY.Sign() == 0 {
			return nil, fmt.Errorf("invalid child point at index %d", index)
		}

		currentX, currentY = childX, childY
		currentChainCode = ir
	}

	return serializeCompressed(currentX, currentY), nil
}

// --- shared helpers ---

// serializeCompressed encodes a secp256k1 or similar point as a 33-byte compressed key.
func serializeCompressed(x, y *big.Int) []byte {
	b := make([]byte, 0, pubKeyBytesLenCompressed)
	format := pubKeyCompressedEven
	if isOdd(y) {
		format = pubKeyCompressedOdd
	}
	b = append(b, format)
	return paddedAppend(b, 32, x.Bytes())
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func paddedAppend(dst []byte, srcPaddedSize int, src []byte) []byte {
	return append(dst, paddedBytes(srcPaddedSize, src)...)
}

func paddedBytes(size int, src []byte) []byte {
	offset := size - len(src)
	tmp := src
	if offset > 0 {
		tmp = make([]byte, size)
		copy(tmp[offset:], src)
	}
	return tmp
}
