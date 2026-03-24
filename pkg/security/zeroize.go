package security

import (
	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/dkg"
)

// ZeroScalar zeroes a kryptology Scalar by replacing its value with the field's
// zero element.  Safe to call with nil.
func ZeroScalar(s curves.Scalar) {
	if s == nil {
		return
	}
	zero := s.Zero()
	// Attempt to mutate s in-place using SetBigInt(0); concrete scalar types
	// implement this by overwriting their internal field.
	if z, err := s.SetBigInt(zero.BigInt()); err == nil {
		_ = z
	}
}

// ZeroAliceDkgOutput zeroes sensitive fields in an AliceOutput.
// Call this after persisting the output to BadgerDB.
func ZeroAliceDkgOutput(out *dkg.AliceOutput) {
	if out == nil {
		return
	}
	ZeroScalar(out.SecretKeyShare)
}

// ZeroBobDkgOutput zeroes sensitive fields in a BobOutput.
func ZeroBobDkgOutput(out *dkg.BobOutput) {
	if out == nil {
		return
	}
	ZeroScalar(out.SecretKeyShare)
}
