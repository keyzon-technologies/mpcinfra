package mpc

// frost_wire.go provides custom JSON serialization for kryptology FROST types.
//
// The kryptology curves.Scalar and curves.Point interfaces do not implement
// json.Marshaler/json.Unmarshaler, so structs that contain them (Round1Bcast,
// Round2Bcast, etc.) cannot be JSON-marshalled with the standard library.
// We encode them as plain byte slices (compressed-point / scalar bytes) and
// reconstruct the concrete types at decode time using the known curve.

import (
	"encoding/json"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	frostdkg "github.com/keyzon-technologies/kryptology/pkg/dkg/frost"
	"github.com/keyzon-technologies/kryptology/pkg/sharing"
	frosted25519 "github.com/keyzon-technologies/kryptology/pkg/ted25519/frost"
)

// ─── DKG Round 1 broadcast ───────────────────────────────────────────────────

type dkgR1Wire struct {
	// Feldman verifier: one compressed-point bytes entry per commitment.
	Comms [][]byte `json:"comms"`
	// ZKP scalars.
	Wi []byte `json:"wi"`
	Ci []byte `json:"ci"`
}

func marshalDkgR1Bcast(bcast *frostdkg.Round1Bcast) ([]byte, error) {
	comms := make([][]byte, len(bcast.Verifiers.Commitments))
	for i, c := range bcast.Verifiers.Commitments {
		comms[i] = c.ToAffineCompressed()
	}
	return json.Marshal(dkgR1Wire{
		Comms: comms,
		Wi:    bcast.Wi.Bytes(),
		Ci:    bcast.Ci.Bytes(),
	})
}

func unmarshalDkgR1Bcast(b []byte, curve *curves.Curve) (*frostdkg.Round1Bcast, error) {
	var w dkgR1Wire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	comms := make([]curves.Point, len(w.Comms))
	for i, cb := range w.Comms {
		pt, err := curve.Point.FromAffineCompressed(cb)
		if err != nil {
			return nil, err
		}
		comms[i] = pt
	}
	wi, err := curve.Scalar.SetBytes(w.Wi)
	if err != nil {
		return nil, err
	}
	ci, err := curve.Scalar.SetBytes(w.Ci)
	if err != nil {
		return nil, err
	}
	return &frostdkg.Round1Bcast{
		Verifiers: &sharing.FeldmanVerifier{Commitments: comms},
		Wi:        wi,
		Ci:        ci,
	}, nil
}

// ─── DKG Round 2 broadcast ───────────────────────────────────────────────────

type dkgR2Wire struct {
	VK      []byte `json:"vk"`
	VkShare []byte `json:"vkShare"`
}

func marshalDkgR2Bcast(bcast *frostdkg.Round2Bcast) ([]byte, error) {
	return json.Marshal(dkgR2Wire{
		VK:      bcast.VerificationKey.ToAffineCompressed(),
		VkShare: bcast.VkShare.ToAffineCompressed(),
	})
}

func unmarshalDkgR2Bcast(b []byte, curve *curves.Curve) (*frostdkg.Round2Bcast, error) {
	var w dkgR2Wire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	vk, err := curve.Point.FromAffineCompressed(w.VK)
	if err != nil {
		return nil, err
	}
	vkShare, err := curve.Point.FromAffineCompressed(w.VkShare)
	if err != nil {
		return nil, err
	}
	return &frostdkg.Round2Bcast{
		VerificationKey: vk,
		VkShare:         vkShare,
	}, nil
}

// ─── Signing Round 1 broadcast ───────────────────────────────────────────────

type signR1Wire struct {
	Di []byte `json:"di"`
	Ei []byte `json:"ei"`
}

func marshalSignR1Bcast(bcast *frosted25519.Round1Bcast) ([]byte, error) {
	return json.Marshal(signR1Wire{
		Di: bcast.Di.ToAffineCompressed(),
		Ei: bcast.Ei.ToAffineCompressed(),
	})
}

func unmarshalSignR1Bcast(b []byte, curve *curves.Curve) (*frosted25519.Round1Bcast, error) {
	var w signR1Wire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	di, err := curve.Point.FromAffineCompressed(w.Di)
	if err != nil {
		return nil, err
	}
	ei, err := curve.Point.FromAffineCompressed(w.Ei)
	if err != nil {
		return nil, err
	}
	return &frosted25519.Round1Bcast{Di: di, Ei: ei}, nil
}

// ─── Signing Round 2 broadcast ───────────────────────────────────────────────

type signR2Wire struct {
	Zi  []byte `json:"zi"`
	Vki []byte `json:"vki"`
}

func marshalSignR2Bcast(bcast *frosted25519.Round2Bcast) ([]byte, error) {
	return json.Marshal(signR2Wire{
		Zi:  bcast.Zi.Bytes(),
		Vki: bcast.Vki.ToAffineCompressed(),
	})
}

func unmarshalSignR2Bcast(b []byte, curve *curves.Curve) (*frosted25519.Round2Bcast, error) {
	var w signR2Wire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	zi, err := curve.Scalar.SetBytes(w.Zi)
	if err != nil {
		return nil, err
	}
	vki, err := curve.Point.FromAffineCompressed(w.Vki)
	if err != nil {
		return nil, err
	}
	return &frosted25519.Round2Bcast{Zi: zi, Vki: vki}, nil
}
