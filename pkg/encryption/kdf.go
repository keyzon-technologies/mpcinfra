package encryption

import (
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters — OWASP minimum for server workloads.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
)

// DeriveKey derives a 32-byte key from password using Argon2id.
// context is a domain-separation string (e.g. "mpcinfra-badger-db" or "mpcinfra-badger-backup").
// The salt is derived deterministically from context via SHA-256, so the same
// password + context always produces the same key — required for at-rest encryption
// where the key must be reproducible across restarts.
func DeriveKey(password, context string) []byte {
	salt := sha256.Sum256([]byte(context))
	return argon2.IDKey(
		[]byte(password),
		salt[:],
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)
}
