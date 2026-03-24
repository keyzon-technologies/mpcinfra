package mpc

// EDDSA message-type constants for FROST protocol messages.
// These are embedded in MpcMsg.MsgType so the receiver can route
// the payload to the correct FROST participant instance.
const (
	// FROST DKG rounds
	FrostDKGRound1    = "frost_dkg_r1"     // all → all  (each participant's Round1 broadcast)
	FrostDKGRound1P2P = "frost_dkg_r1_p2p" // each → each (unicast Shamir share)
	FrostDKGRound2    = "frost_dkg_r2"     // all → all  (Round2 broadcast)

	// FROST signing rounds
	FrostSignRound1 = "frost_sign_r1" // all → all  (each signer's commitment)
	FrostSignRound2 = "frost_sign_r2" // all → all  (each signer's partial signature)

	// FROST resharing rounds
	FrostReshareRound1 = "frost_reshare_r1" // old → all  (old committee's round-1 outputs)
	FrostReshareRound2 = "frost_reshare_r2" // old → each  (refreshed Shamir shares)
	FrostReshareRound3 = "frost_reshare_r3" // new → all  (new committee acknowledgements)
)

// FrostDKGRoundCount is the number of broadcast rounds in FROST DKG.
const FrostDKGRoundCount = 2

// FrostSignRoundCount is the number of rounds in FROST signing.
const FrostSignRoundCount = 2

// FrostReshareRoundCount is the number of rounds in FROST resharing.
const FrostReshareRoundCount = 3
