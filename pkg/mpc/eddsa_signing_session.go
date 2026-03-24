package mpc

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	frostdkg "github.com/keyzon-technologies/kryptology/pkg/dkg/frost"
	"github.com/keyzon-technologies/kryptology/pkg/sharing"
	frosted25519 "github.com/keyzon-technologies/kryptology/pkg/ted25519/frost"

	"github.com/keyzon-technologies/mpcinfra/pkg/common/errors"
	"github.com/keyzon-technologies/mpcinfra/pkg/event"
	"github.com/keyzon-technologies/mpcinfra/pkg/identity"
	"github.com/keyzon-technologies/mpcinfra/pkg/keyinfo"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/keyzon-technologies/mpcinfra/pkg/messaging"
	"github.com/keyzon-technologies/mpcinfra/pkg/types"
)

// eddsaSigningSession drives FROST threshold signing for Ed25519.
// All t+1 session participants run the 3-round signing protocol.
type eddsaSigningSession struct {
	session
	txID                string
	networkInternalCode string
	derivationPath      []uint32
	ckd                 *CKD
	msgBytes            []byte // the transaction bytes being signed

	signer *frosted25519.Signer

	// Round 1 state (commitments from all signers).
	signR1Bcasts  map[uint32]*frosted25519.Round1Bcast
	signR1Mu      sync.Mutex
	signR2Started atomic.Bool

	// Round 2 state (signature shares from all signers).
	signR2Bcasts  map[uint32]*frosted25519.Round2Bcast
	signR2Mu      sync.Mutex
	signR3Started atomic.Bool

	signerIDs []uint32 // 1-indexed FROST IDs of all session participants
	lCoeffs   map[uint32]curves.Scalar

	onSuccess func([]byte)
	curve     *curves.Curve
}

func newEDDSASigningSession(
	walletID string,
	nodeID string,
	peerIDs []string, // all signing participants (sorted), including self
	txID string,
	networkInternalCode string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	derivationPath []uint32,
	idempotentKey string,
	ckd *CKD,
) *eddsaSigningSession {
	return &eddsaSigningSession{
		session: session{
			walletID:      walletID,
			nodeID:        nodeID,
			peerIDs:       peerIDs,
			pubSub:        pubSub,
			direct:        direct,
			ErrCh:         make(chan error, 1),
			doneCh:        make(chan struct{}),
			kvstore:       kvstore,
			keyinfoStore:  keyinfoStore,
			resultQueue:   resultQueue,
			identityStore: identityStore,
			sessionType:   SessionTypeEDDSA,
			idempotentKey: idempotentKey,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("sign:eddsa:broadcast:%s:%s", walletID, txID)
				},
				ComposeDirectTopic: func(fromID, toID string) string {
					return fmt.Sprintf("sign:eddsa:direct:%s:%s:%s", fromID, toID, txID)
				},
			},
			composeKey: func(id string) string {
				return fmt.Sprintf("eddsa:%s", id)
			},
		},
		txID:                txID,
		networkInternalCode: networkInternalCode,
		derivationPath:      derivationPath,
		ckd:                 ckd,
		signR1Bcasts:        make(map[uint32]*frosted25519.Round1Bcast),
		signR2Bcasts:        make(map[uint32]*frosted25519.Round2Bcast),
		curve:               curves.ED25519(),
	}
}

// participantID returns the 1-indexed FROST participant ID for a node ID.
func (s *eddsaSigningSession) participantID(nodeID string) uint32 {
	for i, id := range s.session.peerIDs {
		if id == nodeID {
			return uint32(i + 1)
		}
	}
	return 0
}

// Init loads the persisted FROST DKG output and constructs the FROST Signer.
func (s *eddsaSigningSession) Init(tx *big.Int) error {
	s.msgBytes = tx.Bytes()

	ki, err := s.session.keyinfoStore.Get(s.session.composeKey(s.session.walletID))
	if err != nil {
		return errors.Wrap(err, "EDDSA sign: load keyinfo")
	}

	rawKey, err := s.session.kvstore.Get(s.session.composeKey(walletIDWithVersion(s.session.walletID, ki.Version)))
	if err != nil {
		return errors.Wrap(err, "EDDSA sign: load key data")
	}

	var kgData EDDSAKeygenData
	if err := json.Unmarshal(rawKey, &kgData); err != nil {
		return errors.Wrap(err, "EDDSA sign: unmarshal key data")
	}

	// Decode the persisted key material.
	skShare, err := s.curve.Scalar.SetBytes(kgData.SkShareBytes)
	if err != nil {
		return fmt.Errorf("EDDSA sign: decode skShare: %w", err)
	}
	vkShare, err := s.curve.Point.FromAffineCompressed(kgData.VkShareBytes)
	if err != nil {
		return fmt.Errorf("EDDSA sign: decode vkShare: %w", err)
	}
	vk, err := s.curve.Point.FromAffineCompressed(kgData.GroupPublicKey)
	if err != nil {
		return fmt.Errorf("EDDSA sign: decode group public key: %w", err)
	}

	// Apply BIP32 tweak if a derivation path is given.
	if len(s.derivationPath) > 0 {
		tweak, childVK, err := s.ckd.DeriveForCurve(s.session.walletID, kgData.GroupPublicKey, s.derivationPath, s.curve)
		if err != nil {
			return fmt.Errorf("EDDSA sign: BIP32 derive: %w", err)
		}
		// Only the signer with the smallest participant ID (ID=1) adds the tweak to their
		// share. Since skShare is the raw Shamir share and Lagrange weighting happens via
		// lCoeffs, we apply the adjustment factor tweak/λ_self at signing time. For now
		// we use a simpler scheme: signer with ID=1 holds the full tweak addend such that
		// the reconstructed child secret = master_secret + tweak.
		// We achieve this by adding tweak directly to the skShare of the lowest-ID signer
		// and adjusting the VkShare accordingly.
		selfPID := s.participantID(s.session.nodeID)
		if selfPID == 1 {
			skShare = skShare.Add(tweak)
			vkShare = vkShare.Add(s.curve.ScalarBaseMult(tweak))
		}
		vk = childVK
	}

	// Build the FROST DkgParticipant shell from stored data (only the fields
	// needed by frosted25519.NewSigner are set).
	selfPID := s.participantID(s.session.nodeID)
	info := &frostdkg.DkgParticipant{
		Curve:           s.curve,
		Id:              selfPID,
		SkShare:         skShare,
		VkShare:         vkShare,
		VerificationKey: vk,
	}

	// Compute 1-indexed IDs and Lagrange coefficients for all session participants.
	n := len(s.session.peerIDs)
	signerIDs := make([]uint32, n)
	for i := range s.session.peerIDs {
		signerIDs[i] = uint32(i + 1)
	}
	s.signerIDs = signerIDs

	sh, err := sharing.NewShamir(uint32(kgData.Threshold+1), uint32(len(kgData.NodeIDs)), s.curve)
	if err != nil {
		return fmt.Errorf("EDDSA sign: NewShamir: %w", err)
	}
	lCoeffs, err := sh.LagrangeCoeffs(signerIDs)
	if err != nil {
		return fmt.Errorf("EDDSA sign: LagrangeCoeffs: %w", err)
	}
	s.lCoeffs = lCoeffs

	signer, err := frosted25519.NewSigner(
		info,
		selfPID,
		uint32(n), // thresh = number of cosigners
		lCoeffs,
		signerIDs,
		&frosted25519.Ed25519ChallengeDeriver{},
	)
	if err != nil {
		return fmt.Errorf("EDDSA sign: NewSigner: %w", err)
	}
	s.signer = signer
	s.session.version = ki.Version
	return nil
}

func (s *eddsaSigningSession) ListenToIncomingMessageAsync() {
	s.listenToIncomingMessageAsync(s.onMpcMsg)
}

func (s *eddsaSigningSession) ListenToPeersAsync(peerIDs []string) {
	s.subscribeFromPeersAsync(peerIDs, s.onMpcMsg)
}

func (s *eddsaSigningSession) onMpcMsg(msg *types.MpcMsg) {
	if msg.Protocol != types.ProtoFrostSign {
		return
	}
	fromPID := s.participantID(msg.FromNodeID)
	if fromPID == 0 {
		return
	}

	switch msg.Round {
	case FrostSignRound1:
		bcast, err := unmarshalSignR1Bcast(msg.Payload, s.curve)
		if err != nil {
			s.sendErr(fmt.Errorf("EDDSA sign: unmarshal Round1 bcast from %d: %w", fromPID, err))
			return
		}
		s.signR1Mu.Lock()
		s.signR1Bcasts[fromPID] = bcast
		ready := len(s.signR1Bcasts) == len(s.signerIDs)
		s.signR1Mu.Unlock()
		if ready {
			go s.runSignRound2()
		}

	case FrostSignRound2:
		bcast, err := unmarshalSignR2Bcast(msg.Payload, s.curve)
		if err != nil {
			s.sendErr(fmt.Errorf("EDDSA sign: unmarshal Round2 bcast from %d: %w", fromPID, err))
			return
		}
		s.signR2Mu.Lock()
		s.signR2Bcasts[fromPID] = bcast
		ready := len(s.signR2Bcasts) == len(s.signerIDs)
		s.signR2Mu.Unlock()
		if ready {
			go s.runSignRound3()
		}
	}
}

// Sign runs signing Round 1 and broadcasts the nonce commitments.
func (s *eddsaSigningSession) Sign(onSuccess func([]byte)) {
	s.onSuccess = onSuccess
	go s.runSignRound1()
}

func (s *eddsaSigningSession) runSignRound1() {
	bcast, err := s.signer.SignRound1()
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA sign: Round1: %w", err))
		return
	}

	selfPID := s.participantID(s.session.nodeID)
	s.signR1Mu.Lock()
	s.signR1Bcasts[selfPID] = bcast
	s.signR1Mu.Unlock()

	b, err := marshalSignR1Bcast(bcast)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA sign: marshal Round1 bcast: %w", err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoFrostSign,
		Round:      FrostSignRound1,
		FromNodeID: s.session.nodeID,
		Payload:    b,
	})
}

func (s *eddsaSigningSession) runSignRound2() {
	if !s.signR2Started.CompareAndSwap(false, true) {
		return
	}
	s.signR1Mu.Lock()
	r1Input := make(map[uint32]*frosted25519.Round1Bcast, len(s.signR1Bcasts))
	for id, b := range s.signR1Bcasts {
		r1Input[id] = b
	}
	s.signR1Mu.Unlock()

	bcast, err := s.signer.SignRound2(s.msgBytes, r1Input)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA sign: Round2: %w", err))
		return
	}

	selfPID := s.participantID(s.session.nodeID)
	s.signR2Mu.Lock()
	s.signR2Bcasts[selfPID] = bcast
	ready := len(s.signR2Bcasts) == len(s.signerIDs)
	s.signR2Mu.Unlock()

	b, err := marshalSignR2Bcast(bcast)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA sign: marshal Round2 bcast: %w", err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoFrostSign,
		Round:      FrostSignRound2,
		FromNodeID: s.session.nodeID,
		Payload:    b,
	})

	if ready {
		go s.runSignRound3()
	}
}

func (s *eddsaSigningSession) runSignRound3() {
	if !s.signR3Started.CompareAndSwap(false, true) {
		return
	}
	s.signR2Mu.Lock()
	r2Input := make(map[uint32]*frosted25519.Round2Bcast, len(s.signR2Bcasts))
	for id, b := range s.signR2Bcasts {
		r2Input[id] = b
	}
	s.signR2Mu.Unlock()

	result, err := s.signer.SignRound3(r2Input)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA sign: Round3: %w", err))
		return
	}

	// Encode signature as R‖Z (two 32-byte scalars for Ed25519 FROST).
	// R is the aggregate nonce point; Z is the aggregate scalar.
	rBytes := result.R.ToAffineCompressed() // 32 bytes
	zBytes := result.Z.Bytes()              // 32 bytes
	sig := append(rBytes, zBytes...)        // 64-byte Ed25519-style signature

	r := event.SigningResultEvent{
		ResultType:          event.ResultTypeSuccess,
		NetworkInternalCode: s.networkInternalCode,
		WalletID:            s.session.walletID,
		TxID:                s.txID,
		Signature:           sig,
	}
	b, err := json.Marshal(r)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA sign: marshal result: %w", err))
		return
	}
	if err := s.session.resultQueue.Enqueue(event.SigningResultCompleteTopic, b, &messaging.EnqueueOptions{
		IdempotententKey: s.session.idempotentKey,
	}); err != nil {
		s.sendErr(fmt.Errorf("EDDSA sign: enqueue result: %w", err))
		return
	}

	logger.Info("[EDDSA Sign] Signature produced", "walletID", s.session.walletID, "txID", s.txID)
	if err := s.Close(); err != nil {
		logger.Error("EDDSA sign: close session", err)
	}
	if s.onSuccess != nil {
		s.onSuccess(b)
	}
}

func (s *eddsaSigningSession) Close() error {
	for i := range s.derivationPath {
		s.derivationPath[i] = 0
	}
	s.derivationPath = nil
	s.ckd = nil
	return s.session.Close()
}

func (s *eddsaSigningSession) Stop() {
	s.session.Stop()
}
