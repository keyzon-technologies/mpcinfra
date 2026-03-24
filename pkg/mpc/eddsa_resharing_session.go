package mpc

// eddsa_resharing_session.go implements proactive FROST re-sharing for Ed25519.
//
// The protocol is based on Shamir polynomial resharing (Desmedt & Frankel, 1990):
//   - Old committee member i holds Shamir share s_i where group key Q = Σ λ_i·s_i·G.
//   - Old member i splits s_i into a new Feldman polynomial g_i of degree t' with g_i(0) = s_i.
//   - Old member i broadcasts Feldman commitments and sends g_i(j) to each new member j.
//   - New member j collects all sub-shares, verifies them, and computes:
//       s_j_new = Σ_{i in old} λ_i · g_i(j)
//   - The group public key Q is preserved: Σ λ_i·g_i(0)·G = Σ λ_i·s_i·G = Q.

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/sharing"

	"github.com/keyzon-technologies/mpcinfra/pkg/identity"
	"github.com/keyzon-technologies/mpcinfra/pkg/keyinfo"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/keyzon-technologies/mpcinfra/pkg/messaging"
	"github.com/keyzon-technologies/mpcinfra/pkg/security"
	"github.com/keyzon-technologies/mpcinfra/pkg/types"
)

// EDDSAReshareSession is the interface exposed to node.go.
type EDDSAReshareSession interface {
	Session
	Init() error
	Reshare(done func())
	GetPubKeyResult() []byte
	GetLegacyCommitteePeers() []string
	WaitForPeersReady() error
	Stop()
}

// eddsaReshareSubShare is the p2p wire type sent by each old member to each new member.
type eddsaReshareSubShare struct {
	// Value is the polynomial evaluation g_i(j) encoded as scalar bytes.
	Value []byte `json:"value"`
}

// eddsaReshareCommitments is broadcast by each old member.
type eddsaReshareCommitments struct {
	// Comms[k] = compressed-point bytes for the k-th Feldman commitment.
	Comms [][]byte `json:"comms"`
}

type eddsaReshareSession struct {
	session
	oldThreshold int
	newThreshold int
	oldPeerIDs   []string // old committee (sorted)
	newPeerIDs   []string // new committee (sorted)
	isNewPeer    bool
	done         func()

	// Accumulated data for new committee members.
	subShareMu       sync.Mutex
	receivedSubShare map[uint32]curves.Scalar  // oldPID → g_i(j)
	receivedComms    map[uint32][]curves.Point // oldPID → Feldman commitments
	finished         atomic.Bool

	curve *curves.Curve
}

// NewEDDSAReshareSession constructs an EdDSA reshare session.
func NewEDDSAReshareSession(
	walletID string,
	nodeID string,
	oldPeerIDs []string,
	newPeerIDs []string,
	oldThreshold int,
	newThreshold int,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	isNewPeer bool,
	oldVersion int,
) *eddsaReshareSession {
	activePeerIDs := oldPeerIDs
	if isNewPeer {
		activePeerIDs = newPeerIDs
	}
	return &eddsaReshareSession{
		session: session{
			walletID:      walletID,
			nodeID:        nodeID,
			peerIDs:       activePeerIDs,
			pubSub:        pubSub,
			direct:        direct,
			version:       oldVersion,
			ErrCh:         make(chan error, 1),
			doneCh:        make(chan struct{}),
			kvstore:       kvstore,
			keyinfoStore:  keyinfoStore,
			resultQueue:   resultQueue,
			identityStore: identityStore,
			sessionType:   SessionTypeEDDSA,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("resharing:broadcast:eddsa:%s", walletID)
				},
				ComposeDirectTopic: func(fromID, toID string) string {
					return fmt.Sprintf("resharing:direct:eddsa:%s:%s:%s", fromID, toID, walletID)
				},
			},
			composeKey: func(id string) string {
				return fmt.Sprintf("eddsa:%s", id)
			},
		},
		oldThreshold:     oldThreshold,
		newThreshold:     newThreshold,
		oldPeerIDs:       oldPeerIDs,
		newPeerIDs:       newPeerIDs,
		isNewPeer:        isNewPeer,
		receivedSubShare: make(map[uint32]curves.Scalar),
		receivedComms:    make(map[uint32][]curves.Point),
		curve:            curves.ED25519(),
	}
}

func (s *eddsaReshareSession) GetLegacyCommitteePeers() []string {
	newSet := make(map[string]bool, len(s.newPeerIDs))
	for _, id := range s.newPeerIDs {
		newSet[id] = true
	}
	var legacy []string
	for _, id := range s.oldPeerIDs {
		if !newSet[id] {
			legacy = append(legacy, id)
		}
	}
	return legacy
}

func (s *eddsaReshareSession) Init() error {
	return nil
}

func (s *eddsaReshareSession) ListenToIncomingMessageAsync() {
	s.listenToIncomingMessageAsync(s.onMpcMsg)
}

func (s *eddsaReshareSession) ListenToPeersAsync(peerIDs []string) {
	s.subscribeFromPeersAsync(peerIDs, s.onMpcMsg)
}

func (s *eddsaReshareSession) onMpcMsg(msg *types.MpcMsg) {
	if msg.Protocol != types.ProtoFrostReshare {
		return
	}
	switch msg.Round {
	case FrostReshareRound1:
		s.handleCommitmentsMsg(msg)
	case FrostReshareRound2:
		s.handleSubShareMsg(msg)
	}
}

// Reshare starts the protocol. Old members split their share and distribute sub-shares.
func (s *eddsaReshareSession) Reshare(done func()) {
	s.done = done

	isOldMember := false
	for _, id := range s.oldPeerIDs {
		if id == s.session.nodeID {
			isOldMember = true
			break
		}
	}
	if isOldMember {
		go s.runOldMemberProtocol()
	}
}

// ─── Old committee ────────────────────────────────────────────────────────────

func (s *eddsaReshareSession) runOldMemberProtocol() {
	rawKey, err := s.session.kvstore.Get(s.session.composeKey(walletIDWithVersion(s.session.walletID, s.session.GetVersion())))
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: load key data: %w", err))
		return
	}
	var kgData EDDSAKeygenData
	if err := json.Unmarshal(rawKey, &kgData); err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: unmarshal key data: %w", err))
		return
	}

	skShare, err := s.curve.Scalar.SetBytes(kgData.SkShareBytes)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: decode skShare: %w", err))
		return
	}

	// Create Feldman polynomial g_i of degree t' with g_i(0) = skShare.
	nNew := len(s.newPeerIDs)
	feldman, err := sharing.NewFeldman(uint32(s.newThreshold+1), uint32(nNew), s.curve)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: NewFeldman: %w", err))
		return
	}
	verifier, subShares, err := feldman.Split(skShare, nil)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: Feldman split: %w", err))
		return
	}

	// Broadcast Feldman commitments.
	comms := make([][]byte, len(verifier.Commitments))
	for i, c := range verifier.Commitments {
		comms[i] = c.ToAffineCompressed()
	}
	commsBytes, err := json.Marshal(eddsaReshareCommitments{Comms: comms})
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: marshal commitments: %w", err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoFrostReshare,
		Round:      FrostReshareRound1,
		FromNodeID: s.session.nodeID,
		Payload:    commsBytes,
	})

	// Send g_i(j) to each new committee member j.
	for newIdx, newPeerID := range s.newPeerIDs {
		share := subShares[newIdx]
		shareBytes, err := json.Marshal(eddsaReshareSubShare{Value: share.Value})
		if err != nil {
			s.sendErr(fmt.Errorf("EDDSA reshare: marshal sub-share for %s: %w", newPeerID, err))
			return
		}
		s.sendMpcMsg(&types.MpcMsg{
			WalletID:   s.session.walletID,
			Protocol:   types.ProtoFrostReshare,
			Round:      FrostReshareRound2,
			FromNodeID: s.session.nodeID,
			ToNodeID:   newPeerID,
			Payload:    shareBytes,
		})
	}
}

// ─── New committee ────────────────────────────────────────────────────────────

func (s *eddsaReshareSession) oldParticipantID(nodeID string) uint32 {
	for i, id := range s.oldPeerIDs {
		if id == nodeID {
			return uint32(i + 1)
		}
	}
	return 0
}

func (s *eddsaReshareSession) handleCommitmentsMsg(msg *types.MpcMsg) {
	fromOldPID := s.oldParticipantID(msg.FromNodeID)
	if fromOldPID == 0 {
		return
	}
	var payload eddsaReshareCommitments
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: unmarshal commitments from %s: %w", msg.FromNodeID, err))
		return
	}
	pts := make([]curves.Point, len(payload.Comms))
	for i, cb := range payload.Comms {
		pt, err := s.curve.Point.FromAffineCompressed(cb)
		if err != nil {
			s.sendErr(fmt.Errorf("EDDSA reshare: decode commitment[%d] from %s: %w", i, msg.FromNodeID, err))
			return
		}
		pts[i] = pt
	}

	s.subShareMu.Lock()
	s.receivedComms[fromOldPID] = pts
	ready := s.allDataReceived()
	s.subShareMu.Unlock()

	if ready {
		go s.computeNewShare()
	}
}

func (s *eddsaReshareSession) handleSubShareMsg(msg *types.MpcMsg) {
	isNew := false
	for _, id := range s.newPeerIDs {
		if id == s.session.nodeID {
			isNew = true
			break
		}
	}
	if !isNew {
		return
	}

	fromOldPID := s.oldParticipantID(msg.FromNodeID)
	if fromOldPID == 0 {
		return
	}
	var payload eddsaReshareSubShare
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: unmarshal sub-share from %s: %w", msg.FromNodeID, err))
		return
	}
	sc, err := s.curve.Scalar.SetBytes(payload.Value)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: decode sub-share from %s: %w", msg.FromNodeID, err))
		return
	}

	s.subShareMu.Lock()
	s.receivedSubShare[fromOldPID] = sc
	ready := s.allDataReceived()
	s.subShareMu.Unlock()

	if ready {
		go s.computeNewShare()
	}
}

// allDataReceived is called with subShareMu held.
func (s *eddsaReshareSession) allDataReceived() bool {
	nOld := len(s.oldPeerIDs)
	return len(s.receivedSubShare) == nOld && len(s.receivedComms) == nOld
}

func (s *eddsaReshareSession) computeNewShare() {
	if !s.finished.CompareAndSwap(false, true) {
		return
	}

	s.subShareMu.Lock()
	subShares := make(map[uint32]curves.Scalar, len(s.receivedSubShare))
	comms := make(map[uint32][]curves.Point, len(s.receivedComms))
	for pid, sc := range s.receivedSubShare {
		subShares[pid] = sc
	}
	for pid, cc := range s.receivedComms {
		comms[pid] = cc
	}
	s.subShareMu.Unlock()

	// Determine self's new participant ID (1-indexed in newPeerIDs).
	selfNewPID := uint32(0)
	for i, id := range s.newPeerIDs {
		if id == s.session.nodeID {
			selfNewPID = uint32(i + 1)
			break
		}
	}
	if selfNewPID == 0 {
		s.sendErr(fmt.Errorf("EDDSA reshare: self not found in new committee"))
		return
	}

	// Compute Lagrange coefficients for the old committee.
	nOld := len(s.oldPeerIDs)
	oldIDs := make([]uint32, nOld)
	for i := range s.oldPeerIDs {
		oldIDs[i] = uint32(i + 1)
	}
	sh, err := sharing.NewShamir(uint32(s.oldThreshold+1), uint32(nOld), s.curve)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: NewShamir: %w", err))
		return
	}
	lCoeffs, err := sh.LagrangeCoeffs(oldIDs)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: LagrangeCoeffs: %w", err))
		return
	}

	// Verify each sub-share against its Feldman commitments:
	// g_i(j)·G == Σ_k (j^k · C_{i,k})
	jBig := new(big.Int).SetUint64(uint64(selfNewPID))
	jScalar, err := s.curve.Scalar.SetBigInt(jBig)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: encode self ID as scalar: %w", err))
		return
	}
	oneBig := big.NewInt(1)
	oneScalar, err := s.curve.Scalar.SetBigInt(oneBig)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: encode scalar 1: %w", err))
		return
	}

	for oldPID, sc := range subShares {
		cc := comms[oldPID]
		// Compute Σ_k (j^k · C_{i,k})
		expected := s.curve.NewIdentityPoint()
		jk := oneScalar // j^0 = 1
		for _, commitment := range cc {
			expected = expected.Add(commitment.Mul(jk))
			jk = jk.Mul(jScalar)
		}
		actual := s.curve.ScalarBaseMult(sc)
		if !actual.Equal(expected) {
			s.sendErr(fmt.Errorf("EDDSA reshare: Feldman verification failed for old participant %d", oldPID))
			return
		}
	}

	// Compute new share: s_j_new = Σ_{i in old} λ_i · g_i(j).
	newSkShare := s.curve.NewScalar()
	for oldPID, sc := range subShares {
		lambda := lCoeffs[oldPID]
		newSkShare = newSkShare.Add(lambda.Mul(sc))
	}

	// Compute new group public key: Σ_{i in old} λ_i · C_{i,0}.
	newGroupPK := s.curve.NewIdentityPoint()
	for oldPID, cc := range comms {
		lambda := lCoeffs[oldPID]
		newGroupPK = newGroupPK.Add(cc[0].Mul(lambda))
	}

	newVkShare := s.curve.ScalarBaseMult(newSkShare)
	newVersion := s.session.GetVersion() + 1

	data := &EDDSAKeygenData{
		GroupPublicKey: newGroupPK.ToAffineCompressed(),
		NodeIDs:        s.newPeerIDs,
		SkShareBytes:   newSkShare.Bytes(),
		VkShareBytes:   newVkShare.ToAffineCompressed(),
		Threshold:      s.newThreshold,
	}
	keyBytes, err := json.Marshal(data)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: marshal new key data: %w", err))
		return
	}
	defer security.ZeroBytes(keyBytes)

	storageKey := s.session.composeKey(walletIDWithVersion(s.session.walletID, newVersion))
	if err := s.session.kvstore.Put(storageKey, keyBytes); err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: persist: %w", err))
		return
	}

	ki := keyinfo.KeyInfo{
		ParticipantPeerIDs: s.newPeerIDs,
		Threshold:          s.newThreshold,
		Version:            newVersion,
	}
	if err := s.session.keyinfoStore.Save(s.session.composeKey(s.session.walletID), &ki); err != nil {
		s.sendErr(fmt.Errorf("EDDSA reshare: save keyinfo: %w", err))
		return
	}

	s.session.pubkeyBytes = data.GroupPublicKey
	logger.Info("[EDDSA Reshare] Complete", "walletID", s.session.walletID, "newVersion", newVersion)

	if err := s.Close(); err != nil {
		logger.Error("EDDSA reshare: close session", err)
	}
	if s.done != nil {
		s.done()
	}
}
