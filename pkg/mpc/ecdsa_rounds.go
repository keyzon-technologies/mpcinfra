package mpc

// ECDSA message-type constants for DKLS19 protocol messages.
// These are embedded in MpcMsg.MsgType so the receiver can route
// the payload to the correct protocol.Iterator instance.
const (
	// DKG pair-setup rounds (Bob initiates, Alice responds)
	DklsDKGRound1 = "dkls_dkg_r1" // Bob → Alice  (Bob's random seed)
	DklsDKGRound2 = "dkls_dkg_r2" // Alice → Bob  (commitment + Alice's seed)
	DklsDKGRound3 = "dkls_dkg_r3" // Bob → Alice  (Bob's Schnorr proof)
	DklsDKGRound4 = "dkls_dkg_r4" // Alice → Bob  (Alice's revealed proof)
	DklsDKGRound5 = "dkls_dkg_r5" // Bob → Alice  (seed-OT round 1)
	DklsDKGRound6 = "dkls_dkg_r6" // Alice → Bob  (seed-OT round 2)
	DklsDKGRound7 = "dkls_dkg_r7" // Bob → Alice  (seed-OT round 3)
	DklsDKGRound8 = "dkls_dkg_r8" // Alice → Bob  (seed-OT round 4)
	DklsDKGRound9 = "dkls_dkg_r9" // Bob → Alice  (seed-OT round 5)

	// Signing rounds (Alice initiates)
	DklsSignRound1 = "dkls_sign_r1" // Alice → Bob  (Alice's random seed)
	DklsSignRound2 = "dkls_sign_r2" // Bob → Alice  (Bob's sign output)
	DklsSignRound3 = "dkls_sign_r3" // Alice → Bob  (Alice's sign message)

	// Refresh rounds (Alice initiates)
	DklsRefreshRound1 = "dkls_refresh_r1" // Alice → Bob  (Alice's addend k_A)
	DklsRefreshRound2 = "dkls_refresh_r2" // Bob → Alice  (Bob's addend + seed-OT r1)
	DklsRefreshRound3 = "dkls_refresh_r3" // Alice → Bob  (seed-OT r2)
	DklsRefreshRound4 = "dkls_refresh_r4" // Bob → Alice  (seed-OT r3)
	DklsRefreshRound5 = "dkls_refresh_r5" // Alice → Bob  (seed-OT r4)
	DklsRefreshRound6 = "dkls_refresh_r6" // Bob → Alice  (seed-OT r5)
)

// DklsDKGRoundCount is the number of rounds in a DKLS19 DKG pair-setup.
const DklsDKGRoundCount = 9

// DklsSignRoundCount is the number of rounds in a DKLS19 signing session.
const DklsSignRoundCount = 3

// DklsRefreshRoundCount is the number of rounds in a DKLS19 refresh session.
const DklsRefreshRoundCount = 6
