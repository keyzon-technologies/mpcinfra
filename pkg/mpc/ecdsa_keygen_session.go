package mpc

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/core/protocol"
	frostdkg "github.com/keyzon-technologies/kryptology/pkg/dkg/frost"
	"github.com/keyzon-technologies/kryptology/pkg/sharing"
	dklsv2 "github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2"

	"github.com/keyzon-technologies/mpcinfra/pkg/encoding"
	"github.com/keyzon-technologies/mpcinfra/pkg/identity"
	"github.com/keyzon-technologies/mpcinfra/pkg/keyinfo"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/keyzon-technologies/mpcinfra/pkg/messaging"
	"github.com/keyzon-technologies/mpcinfra/pkg/security"
	"github.com/keyzon-technologies/mpcinfra/pkg/types"
)

// KeyGenSession is the interface exposed to node.go.
type KeyGenSession interface {
	Session

	Init()
	GenerateKey(done func())
	GetPubKeyResult() []byte
	WaitForPeersReady() error
}

// ─── Persisted storage types ─────────────────────────────────────────────────

// DklsPairData holds one node's DKLS19 DKG output for a single signing pair.
// Exactly one of AliceMsg / BobMsg is set, depending on the node's role.
type DklsPairData struct {
	AliceMsg []byte `json:"alice,omitempty"` // encoded *protocol.Message from AliceDkg.Result
	BobMsg   []byte `json:"bob,omitempty"`   // encoded *protocol.Message from BobDkg.Result
}

// ECDSAKeygenData is the per-wallet data persisted in BadgerDB after ECDSA keygen.
type ECDSAKeygenData struct {
	// GroupPublicKey is the secp256k1 group public key Q = x·G (64-byte X‖Y).
	GroupPublicKey []byte `json:"groupPublicKey"`

	// NodeIDs is the sorted list of all participant node IDs.
	// Position i (0-indexed) corresponds to FROST participant ID i+1.
	NodeIDs []string `json:"nodeIDs"`

	// ShamirShare is this node's raw Shamir share from FROST DKG.
	ShamirShare *sharing.ShamirShare `json:"shamirShare"`

	// Pairs maps pairKey(alice,bob) → per-pair DKLS19 DKG output.
	Pairs map[string]*DklsPairData `json:"pairs"`
}

// ─── Session ─────────────────────────────────────────────────────────────────

type ecdsaKeygenSession struct {
	session
	threshold int

	// FROST DKG state (phase 1)
	frostParticipant *frostdkg.DkgParticipant
	frostR1Bcasts    map[uint32]*frostdkg.Round1Bcast // broadcast from all peers
	frostR1P2P       map[uint32]*sharing.ShamirShare  // p2p shares received by self
	frostR2Bcasts    map[uint32]*frostdkg.Round2Bcast
	frostMu          sync.Mutex
	frostR2Started   atomic.Bool // guards runFrostRound2 from being called twice
	shamirShare      *sharing.ShamirShare
	verificationKey  curves.Point
	done             func() // called when all phases complete

	// DKLS19 pair setup state (phase 2 — started after FROST finishes)
	aliceIterators   map[string]*dklsv2.AliceDkg // pairKey → iterator (self is Alice)
	bobIterators     map[string]*dklsv2.BobDkg   // pairKey → iterator (self is Bob)
	pairsMu          sync.Mutex
	pairMutexes      map[string]*sync.Mutex // one mutex per pair key
	pairsComplete    map[string]bool        // marks which pairs have finished
	persistOnce      sync.Once              // ensure persistAndFinish runs exactly once
	pairSetupStarted atomic.Bool            // guards startPairSetupPhase from being called twice
	pairSetupReady   atomic.Bool            // set after iterators are populated
	pendingPairMsgs  []*types.MpcMsg        // messages buffered before pair setup was ready

	curve *curves.Curve
}

func newECDSAKeygenSession(
	walletID string,
	nodeID string,
	peerIDs []string, // all participants, sorted lexicographically
	threshold int,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *ecdsaKeygenSession {
	println("")
	println("")
	println("")
	println("")
	println("")

	println("La eleee")
	println(nodeID)
	println(peerIDs)

	println("")
	println("")
	println("")
	println("")
	println("")

	return &ecdsaKeygenSession{
		session: session{
			walletID:      walletID,
			nodeID:        nodeID,
			peerIDs:       peerIDs,
			pubSub:        pubSub,
			direct:        direct,
			version:       DefaultVersion,
			ErrCh:         make(chan error, 1),
			doneCh:        make(chan struct{}),
			kvstore:       kvstore,
			keyinfoStore:  keyinfoStore,
			resultQueue:   resultQueue,
			identityStore: identityStore,
			sessionType:   SessionTypeECDSA,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("keygen:broadcast:ecdsa:%s", walletID)
				},
				ComposeDirectTopic: func(fromID, toID string) string {
					return fmt.Sprintf("keygen:direct:ecdsa:%s:%s:%s", fromID, toID, walletID)
				},
			},
			composeKey: func(id string) string {
				return fmt.Sprintf("ecdsa:%s", id)
			},
		},
		threshold:      threshold,
		frostR1Bcasts:  make(map[uint32]*frostdkg.Round1Bcast),
		frostR1P2P:     make(map[uint32]*sharing.ShamirShare),
		frostR2Bcasts:  make(map[uint32]*frostdkg.Round2Bcast),
		aliceIterators: make(map[string]*dklsv2.AliceDkg),
		bobIterators:   make(map[string]*dklsv2.BobDkg),
		pairMutexes:    make(map[string]*sync.Mutex),
		pairsComplete:  make(map[string]bool),
		curve:          curves.K256(),
	}
}

// participantID returns the 1-indexed FROST participant ID for a node ID.
func (s *ecdsaKeygenSession) participantID(nodeID string) uint32 {
	for i, id := range s.session.peerIDs {
		if id == nodeID {
			return uint32(i + 1)
		}
	}
	return 0
}

// nodeIDOf maps a uint32 participant ID back to a node ID string.
func (s *ecdsaKeygenSession) nodeIDOf(pid uint32) string {
	if pid == 0 || int(pid) > len(s.session.peerIDs) {
		return ""
	}
	return s.session.peerIDs[pid-1]
}

// selfID returns this node's FROST participant ID.
func (s *ecdsaKeygenSession) selfID() uint32 {
	return s.participantID(s.session.nodeID)
}

func (s *ecdsaKeygenSession) Init() {
	selfID := s.selfID()
	others := make([]uint32, 0, len(s.session.peerIDs)-1)
	for i, id := range s.session.peerIDs {
		if id != s.session.nodeID {
			others = append(others, uint32(i+1))
		}
	}

	var err error
	s.frostParticipant, err = frostdkg.NewDkgParticipant(
		selfID,
		uint32(s.threshold+1), // Feldman threshold = t+1
		"1",                   // context string (fixed per protocol version)
		s.curve,
		others...,
	)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: FROST DKG init: %w", err))
		return
	}
	logger.Infof("[ECDSA Keygen] Initialized FROST DKG selfID=%d, walletID=%s", selfID, s.session.walletID)
}

func (s *ecdsaKeygenSession) ListenToIncomingMessageAsync() {
	s.listenToIncomingMessageAsync(s.onMpcMsg)
}

func (s *ecdsaKeygenSession) ListenToPeersAsync(peerIDs []string) {
	s.subscribeFromPeersAsync(peerIDs, s.onMpcMsg)
}

func (s *ecdsaKeygenSession) onMpcMsg(msg *types.MpcMsg) {
	switch msg.Protocol {
	case types.ProtoDklsGroupDKG:
		s.handleFrostMsg(msg)
	case types.ProtoDklsPairSetup:
		s.handleDklsPairMsg(msg)
	default:
		logger.Warn("ECDSA Keygen: unknown protocol", "protocol", msg.Protocol)
	}
}

// GenerateKey drives the two-phase keygen and calls done() when finished.
func (s *ecdsaKeygenSession) GenerateKey(done func()) {
	s.done = done
	go s.runFrostRound1()
}

// ─── Phase 1: FROST DKG ───────────────────────────────────────────────────────

func (s *ecdsaKeygenSession) runFrostRound1() {
	bcast, p2pSend, err := s.frostParticipant.Round1(nil)
	if err != nil {
		println("")
		println("")
		println("")

		s.sendErr(fmt.Errorf("ECDSA keygen: FROST Round1: %w", err))

		println("")
		println("")
		println("")
		return
	}

	// Record own broadcast.
	selfID := s.selfID()
	s.frostMu.Lock()
	s.frostR1Bcasts[selfID] = bcast
	s.frostMu.Unlock()

	// Broadcast Round1Bcast to all peers.
	bcastBytes, err := marshalDkgR1Bcast(bcast)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: marshal FROST Round1 bcast: %w", err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoDklsGroupDKG,
		Round:      FrostDKGRound1,
		FromNodeID: s.session.nodeID,
		// ToNodeID empty → broadcast
		Payload: bcastBytes,
	})

	// Send p2p ShamirShares to each peer.
	for peerParticipantID, share := range p2pSend {
		shareBytes, err := json.Marshal(share)
		if err != nil {
			println("")
			println("")
			println("")

			s.sendErr(fmt.Errorf("ECDSA keygen: marshal FROST p2p share: %w", err))

			println("")
			println("")
			println("")
			return
		}
		toNodeID := s.nodeIDOf(peerParticipantID)
		s.sendMpcMsg(&types.MpcMsg{
			WalletID:   s.session.walletID,
			Protocol:   types.ProtoDklsGroupDKG,
			Round:      FrostDKGRound1P2P,
			FromNodeID: s.session.nodeID,
			ToNodeID:   toNodeID,
			Payload:    shareBytes,
		})
	}
}

func (s *ecdsaKeygenSession) handleFrostMsg(msg *types.MpcMsg) {
	fromPID := s.participantID(msg.FromNodeID)
	if fromPID == 0 {
		logger.Warn("ECDSA Keygen: unknown FROST sender", "from", msg.FromNodeID)
		return
	}

	switch msg.Round {
	case FrostDKGRound1:
		bcast, err := unmarshalDkgR1Bcast(msg.Payload, s.curve)
		if err != nil {
			s.sendErr(fmt.Errorf("ECDSA keygen: unmarshal FROST Round1 bcast: %w", err))
			return
		}
		s.frostMu.Lock()
		s.frostR1Bcasts[fromPID] = bcast
		ready := s.frostRound1Ready()
		s.frostMu.Unlock()
		if ready {
			go s.runFrostRound2()
		}

	case FrostDKGRound1P2P:
		var share sharing.ShamirShare
		if err := json.Unmarshal(msg.Payload, &share); err != nil {
			s.sendErr(fmt.Errorf("ECDSA keygen: unmarshal FROST p2p share: %w", err))
			return
		}
		s.frostMu.Lock()
		s.frostR1P2P[fromPID] = &share
		ready := s.frostRound1Ready()
		s.frostMu.Unlock()
		if ready {
			go s.runFrostRound2()
		}

	case FrostDKGRound2:
		bcast, err := unmarshalDkgR2Bcast(msg.Payload, s.curve)
		if err != nil {
			s.sendErr(fmt.Errorf("ECDSA keygen: unmarshal FROST Round2 bcast: %w", err))
			return
		}
		s.frostMu.Lock()
		s.frostR2Bcasts[fromPID] = bcast
		ready := len(s.frostR2Bcasts) == len(s.session.peerIDs)
		s.frostMu.Unlock()
		if ready && s.pairSetupStarted.CompareAndSwap(false, true) {
			go s.startPairSetupPhase()
		}
	}
}

// frostRound1Ready returns true when we've received all Round1 bcasts and all p2p shares.
// Must be called with frostMu held.
func (s *ecdsaKeygenSession) frostRound1Ready() bool {
	n := len(s.session.peerIDs)
	return len(s.frostR1Bcasts) == n && len(s.frostR1P2P) == n-1
}

func (s *ecdsaKeygenSession) runFrostRound2() {
	if !s.frostR2Started.CompareAndSwap(false, true) {
		return // already running
	}

	s.frostMu.Lock()
	// Build inputs: all bcasts except self, all p2p shares received.
	selfID := s.selfID()
	bcasts := make(map[uint32]*frostdkg.Round1Bcast, len(s.frostR1Bcasts)-1)
	for pid, b := range s.frostR1Bcasts {
		if pid != selfID {
			bcasts[pid] = b
		}
	}
	p2p := make(map[uint32]*sharing.ShamirShare, len(s.frostR1P2P))
	for pid, sh := range s.frostR1P2P {
		p2p[pid] = sh
	}
	s.frostMu.Unlock()

	r2Bcast, err := s.frostParticipant.Round2(bcasts, p2p)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: FROST Round2: %w", err))
		return
	}

	// Record own Round2 broadcast.
	s.frostMu.Lock()
	s.frostR2Bcasts[selfID] = r2Bcast
	ready := len(s.frostR2Bcasts) == len(s.session.peerIDs)
	s.frostMu.Unlock()

	// Persist Shamir share and group key from FROST participant.
	s.shamirShare = &sharing.ShamirShare{
		Id:    s.frostParticipant.Id,
		Value: s.frostParticipant.SkShare.Bytes(),
	}
	s.verificationKey = s.frostParticipant.VerificationKey

	// Broadcast Round2Bcast.
	r2Bytes, err := marshalDkgR2Bcast(r2Bcast)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: marshal FROST Round2 bcast: %w", err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoDklsGroupDKG,
		Round:      FrostDKGRound2,
		FromNodeID: s.session.nodeID,
		Payload:    r2Bytes,
	})

	if ready && s.pairSetupStarted.CompareAndSwap(false, true) {
		go s.startPairSetupPhase()
	}
}

// ─── Phase 2: DKLS19 pair setup ──────────────────────────────────────────────

func (s *ecdsaKeygenSession) startPairSetupPhase() {
	if s.shamirShare == nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: phase 2 started before FROST share is ready"))
		return
	}

	selfID := s.selfID()
	n := len(s.session.peerIDs)

	// Compute Lagrange shamir wrapper (only needs curve, threshold/limit not used in LagrangeCoeffs).
	sh, err := sharing.NewShamir(uint32(s.threshold+1), uint32(n), s.curve)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: NewShamir for Lagrange: %w", err))
		return
	}

	selfSkShare, err := s.curve.Scalar.SetBytes(s.shamirShare.Value)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: decode own Shamir share: %w", err))
		return
	}

	// Iterate over all n*(n-1)/2 pairs.
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			aliceNodeID := s.session.peerIDs[i]
			bobNodeID := s.session.peerIDs[j]
			alicePID := uint32(i + 1)
			bobPID := uint32(j + 1)
			key := pairKey(aliceNodeID, bobNodeID)

			if selfID != alicePID && selfID != bobPID {
				continue // this node is not in this pair
			}

			// Compute Lagrange coefficient for self in this pair.
			coeffs, err := sh.LagrangeCoeffs([]uint32{alicePID, bobPID})
			if err != nil {
				s.sendErr(fmt.Errorf("ECDSA keygen: Lagrange for pair %s: %w", key, err))
				return
			}
			lCoeff, ok := coeffs[selfID]
			if !ok {
				s.sendErr(fmt.Errorf("ECDSA keygen: no Lagrange coeff for self in pair %s", key))
				return
			}

			weightedShare := lCoeff.Mul(selfSkShare)

			s.pairMutexes[key] = &sync.Mutex{}
			if selfID == alicePID {
				alice := dklsv2.NewAliceDkgWithSecret(s.curve, weightedShare, dklsv2.Version2)
				s.aliceIterators[key] = alice
			} else {
				bob := dklsv2.NewBobDkgWithSecret(s.curve, weightedShare, dklsv2.Version2)
				s.bobIterators[key] = bob
				// Bob initiates; run Round1 immediately.
				go s.sendDklsIteratorMsg(key, aliceNodeID, bobNodeID, bob, nil, aliceNodeID)
			}
		}
	}

	// Mark iterators as ready, then replay any messages that arrived before setup.
	s.pairSetupReady.Store(true)
	s.pairsMu.Lock()
	pending := s.pendingPairMsgs
	s.pendingPairMsgs = nil
	s.pairsMu.Unlock()
	for _, m := range pending {
		var protMsg protocol.Message
		if err := json.Unmarshal(m.Payload, &protMsg); err != nil {
			s.sendErr(fmt.Errorf("DKLS pair setup (buffered) %s: unmarshal msg: %w", pairKey(m.PairAlice, m.PairBob), err))
			return
		}
		s.dispatchDklsPairMsg(m, &protMsg)
	}
}

// sendDklsIteratorMsg advances an iterator and sends the result to toNodeID.
// For Bob (initiator): call with input=nil to start.
func (s *ecdsaKeygenSession) sendDklsIteratorMsg(
	key, aliceNodeID, bobNodeID string,
	iter interface {
		Next(*protocol.Message) (*protocol.Message, error)
	},
	input *protocol.Message,
	toNodeID string,
) {
	if mu, ok := s.pairMutexes[key]; ok {
		mu.Lock()
		defer mu.Unlock()
	}
	reply, err := iter.Next(input)
	if err != nil {
		s.sendErr(fmt.Errorf("DKLS pair setup %s: Next: %w", key, err))
		return
	}
	if reply == nil {
		// Iterator is done — signal completion for this pair.
		s.markPairComplete(key)
		return
	}
	replyBytes, err := json.Marshal(reply)
	if err != nil {
		s.sendErr(fmt.Errorf("DKLS pair setup %s: marshal reply: %w", key, err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoDklsPairSetup,
		PairAlice:  aliceNodeID,
		PairBob:    bobNodeID,
		FromNodeID: s.session.nodeID,
		ToNodeID:   toNodeID,
		Payload:    replyBytes,
	})
}

func (s *ecdsaKeygenSession) handleDklsPairMsg(msg *types.MpcMsg) {
	key := pairKey(msg.PairAlice, msg.PairBob)

	var protMsg protocol.Message
	if err := json.Unmarshal(msg.Payload, &protMsg); err != nil {
		s.sendErr(fmt.Errorf("DKLS pair setup %s: unmarshal msg: %w", key, err))
		return
	}

	if !s.pairSetupReady.Load() {
		// Iterators not yet populated — buffer the message and replay after setup.
		s.pairsMu.Lock()
		s.pendingPairMsgs = append(s.pendingPairMsgs, msg)
		s.pairsMu.Unlock()
		return
	}

	s.dispatchDklsPairMsg(msg, &protMsg)
}

func (s *ecdsaKeygenSession) dispatchDklsPairMsg(msg *types.MpcMsg, protMsg *protocol.Message) {
	key := pairKey(msg.PairAlice, msg.PairBob)
	if msg.PairAlice == s.session.nodeID {
		alice, ok := s.aliceIterators[key]
		if !ok {
			logger.Warn("DKLS pair setup: unknown Alice pair", "key", key)
			return
		}
		go s.sendDklsIteratorMsg(key, msg.PairAlice, msg.PairBob, alice, protMsg, msg.PairBob)
	} else if msg.PairBob == s.session.nodeID {
		bob, ok := s.bobIterators[key]
		if !ok {
			logger.Warn("DKLS pair setup: unknown Bob pair", "key", key)
			return
		}
		go s.sendDklsIteratorMsg(key, msg.PairAlice, msg.PairBob, bob, protMsg, msg.PairAlice)
	}
}

// markPairComplete records that a pair has finished and triggers persistence when all are done.
func (s *ecdsaKeygenSession) markPairComplete(key string) {
	s.pairsMu.Lock()
	s.pairsComplete[key] = true
	total := len(s.aliceIterators) + len(s.bobIterators)
	done := len(s.pairsComplete)
	s.pairsMu.Unlock()

	if done >= total {
		s.persistOnce.Do(func() { go s.persistAndFinish() })
	}
}

// persistAndFinish saves the full keygen output to BadgerDB.
func (s *ecdsaKeygenSession) persistAndFinish() {
	pairs := make(map[string]*DklsPairData, len(s.aliceIterators)+len(s.bobIterators))

	for key, alice := range s.aliceIterators {
		resultMsg, err := alice.Result(dklsv2.Version2)
		if err != nil {
			s.sendErr(fmt.Errorf("DKLS pair setup %s: Alice.Result: %w", key, err))
			return
		}
		b, err := json.Marshal(resultMsg)
		if err != nil {
			s.sendErr(fmt.Errorf("DKLS pair setup %s: marshal Alice result: %w", key, err))
			return
		}
		pairs[key] = &DklsPairData{AliceMsg: b}
	}

	for key, bob := range s.bobIterators {
		resultMsg, err := bob.Result(dklsv2.Version2)
		if err != nil {
			s.sendErr(fmt.Errorf("DKLS pair setup %s: Bob.Result: %w", key, err))
			return
		}
		b, err := json.Marshal(resultMsg)
		if err != nil {
			s.sendErr(fmt.Errorf("DKLS pair setup %s: marshal Bob result: %w", key, err))
			return
		}
		if existing, ok := pairs[key]; ok {
			existing.BobMsg = b
		} else {
			pairs[key] = &DklsPairData{BobMsg: b}
		}
	}

	pubKeyBytes, err := encoding.EncodeS256Point(s.verificationKey)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: encode group public key: %w", err))
		return
	}

	data := &ECDSAKeygenData{
		GroupPublicKey: pubKeyBytes,
		NodeIDs:        s.session.peerIDs,
		ShamirShare:    s.shamirShare,
		Pairs:          pairs,
	}

	keyBytes, err := json.Marshal(data)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: marshal output: %w", err))
		return
	}
	defer security.ZeroBytes(keyBytes)

	storageKey := s.session.composeKey(walletIDWithVersion(s.session.walletID, s.session.GetVersion()))
	if err := s.session.kvstore.Put(storageKey, keyBytes); err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: persist: %w", err))
		return
	}

	ki := keyinfo.KeyInfo{
		ParticipantPeerIDs: s.session.peerIDs,
		Threshold:          s.threshold,
		Version:            s.session.GetVersion(),
	}
	if err := s.session.keyinfoStore.Save(s.session.composeKey(s.session.walletID), &ki); err != nil {
		s.sendErr(fmt.Errorf("ECDSA keygen: save keyinfo: %w", err))
		return
	}

	s.session.pubkeyBytes = pubKeyBytes
	logger.Info("[ECDSA Keygen] Key generation complete", "walletID", s.session.walletID)

	if err := s.Close(); err != nil {
		logger.Error("ECDSA keygen: close session", err)
	}
	if s.done != nil {
		s.done()
	}
}
