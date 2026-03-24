package mpc

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	frostdkg "github.com/keyzon-technologies/kryptology/pkg/dkg/frost"
	"github.com/keyzon-technologies/kryptology/pkg/sharing"

	"github.com/keyzon-technologies/mpcinfra/pkg/identity"
	"github.com/keyzon-technologies/mpcinfra/pkg/keyinfo"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/keyzon-technologies/mpcinfra/pkg/messaging"
	"github.com/keyzon-technologies/mpcinfra/pkg/security"
	"github.com/keyzon-technologies/mpcinfra/pkg/types"
)

// EDDSAKeygenData is the per-wallet data persisted in BadgerDB after EdDSA keygen.
type EDDSAKeygenData struct {
	// GroupPublicKey is the Ed25519 group public key (32-byte compressed point).
	GroupPublicKey []byte `json:"groupPublicKey"`
	// NodeIDs is the sorted list of all participant node IDs.
	// Position i (0-indexed) corresponds to FROST participant ID i+1.
	NodeIDs []string `json:"nodeIDs"`
	// SkShareBytes is this node's FROST secret key share (32-byte scalar).
	SkShareBytes []byte `json:"skShare"`
	// VkShareBytes is this node's FROST verification key share (32-byte compressed point).
	VkShareBytes []byte `json:"vkShare"`
	// Threshold is t (signing requires t+1 participants).
	Threshold int `json:"threshold"`
}

// ─── Session ─────────────────────────────────────────────────────────────────

type eddsaKeygenSession struct {
	session
	threshold int

	// FROST DKG state
	frostParticipant *frostdkg.DkgParticipant
	frostR1Bcasts    map[uint32]*frostdkg.Round1Bcast
	frostR1P2P       map[uint32]*sharing.ShamirShare
	frostR2Bcasts    map[uint32]*frostdkg.Round2Bcast
	frostMu          sync.Mutex
	frostR2Started   atomic.Bool

	done func()

	curve *curves.Curve
}

func newEDDSAKeygenSession(
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
) *eddsaKeygenSession {
	return &eddsaKeygenSession{
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
			sessionType:   SessionTypeEDDSA,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("keygen:broadcast:eddsa:%s", walletID)
				},
				ComposeDirectTopic: func(fromID, toID string) string {
					return fmt.Sprintf("keygen:direct:eddsa:%s:%s:%s", fromID, toID, walletID)
				},
			},
			composeKey: func(id string) string {
				return fmt.Sprintf("eddsa:%s", id)
			},
		},
		threshold:     threshold,
		frostR1Bcasts: make(map[uint32]*frostdkg.Round1Bcast),
		frostR1P2P:    make(map[uint32]*sharing.ShamirShare),
		frostR2Bcasts: make(map[uint32]*frostdkg.Round2Bcast),
		curve:         curves.ED25519(),
	}
}

// participantID returns the 1-indexed FROST participant ID for a node ID string.
func (s *eddsaKeygenSession) participantID(nodeID string) uint32 {
	for i, id := range s.session.peerIDs {
		if id == nodeID {
			return uint32(i + 1)
		}
	}
	return 0
}

// nodeIDOf maps a 1-indexed participant ID back to a node ID string.
func (s *eddsaKeygenSession) nodeIDOf(pid uint32) string {
	if pid == 0 || int(pid) > len(s.session.peerIDs) {
		return ""
	}
	return s.session.peerIDs[pid-1]
}

// selfID returns this node's FROST participant ID.
func (s *eddsaKeygenSession) selfID() uint32 {
	return s.participantID(s.session.nodeID)
}

func (s *eddsaKeygenSession) Init() {
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
		"eddsa-keygen-v1",
		s.curve,
		others...,
	)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA keygen: FROST DKG init: %w", err))
		return
	}
	logger.Infof("[EDDSA Keygen] Initialized FROST DKG selfID=%d, walletID=%s", selfID, s.session.walletID)
}

func (s *eddsaKeygenSession) ListenToIncomingMessageAsync() {
	s.listenToIncomingMessageAsync(s.onMpcMsg)
}

func (s *eddsaKeygenSession) ListenToPeersAsync(peerIDs []string) {
	s.subscribeFromPeersAsync(peerIDs, s.onMpcMsg)
}

func (s *eddsaKeygenSession) onMpcMsg(msg *types.MpcMsg) {
	if msg.Protocol != types.ProtoFrostDKG {
		return
	}
	s.handleFrostMsg(msg)
}

// GenerateKey starts the FROST DKG and calls done() when the key is persisted.
func (s *eddsaKeygenSession) GenerateKey(done func()) {
	s.done = done
	go s.runFrostRound1()
}

// ─── FROST DKG ────────────────────────────────────────────────────────────────

func (s *eddsaKeygenSession) runFrostRound1() {
	bcast, p2pSend, err := s.frostParticipant.Round1(nil)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA keygen: FROST Round1: %w", err))
		return
	}

	selfID := s.selfID()
	s.frostMu.Lock()
	s.frostR1Bcasts[selfID] = bcast
	s.frostMu.Unlock()

	bcastBytes, err := marshalDkgR1Bcast(bcast)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA keygen: marshal FROST Round1 bcast: %w", err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoFrostDKG,
		Round:      FrostDKGRound1,
		FromNodeID: s.session.nodeID,
		Payload:    bcastBytes,
	})

	for peerPID, share := range p2pSend {
		shareBytes, err := json.Marshal(share)
		if err != nil {
			s.sendErr(fmt.Errorf("EDDSA keygen: marshal FROST p2p share: %w", err))
			return
		}
		toNodeID := s.nodeIDOf(peerPID)
		s.sendMpcMsg(&types.MpcMsg{
			WalletID:   s.session.walletID,
			Protocol:   types.ProtoFrostDKG,
			Round:      FrostDKGRound1P2P,
			FromNodeID: s.session.nodeID,
			ToNodeID:   toNodeID,
			Payload:    shareBytes,
		})
	}
}

func (s *eddsaKeygenSession) handleFrostMsg(msg *types.MpcMsg) {
	fromPID := s.participantID(msg.FromNodeID)
	if fromPID == 0 {
		logger.Warn("EDDSA Keygen: unknown FROST sender", "from", msg.FromNodeID)
		return
	}

	switch msg.Round {
	case FrostDKGRound1:
		bcast, err := unmarshalDkgR1Bcast(msg.Payload, s.curve)
		if err != nil {
			s.sendErr(fmt.Errorf("EDDSA keygen: unmarshal FROST Round1 bcast: %w", err))
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
			s.sendErr(fmt.Errorf("EDDSA keygen: unmarshal FROST p2p share: %w", err))
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
			s.sendErr(fmt.Errorf("EDDSA keygen: unmarshal FROST Round2 bcast: %w", err))
			return
		}
		s.frostMu.Lock()
		s.frostR2Bcasts[fromPID] = bcast
		ready := len(s.frostR2Bcasts) == len(s.session.peerIDs)
		s.frostMu.Unlock()
		if ready {
			go s.persistAndFinish()
		}
	}
}

// frostRound1Ready reports whether all Round1 data has arrived. Caller must hold frostMu.
func (s *eddsaKeygenSession) frostRound1Ready() bool {
	n := len(s.session.peerIDs)
	return len(s.frostR1Bcasts) == n && len(s.frostR1P2P) == n-1
}

func (s *eddsaKeygenSession) runFrostRound2() {
	if !s.frostR2Started.CompareAndSwap(false, true) {
		return // already running
	}

	s.frostMu.Lock()
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
		s.sendErr(fmt.Errorf("EDDSA keygen: FROST Round2: %w", err))
		return
	}

	s.frostMu.Lock()
	s.frostR2Bcasts[selfID] = r2Bcast
	ready := len(s.frostR2Bcasts) == len(s.session.peerIDs)
	s.frostMu.Unlock()

	r2Bytes, err := marshalDkgR2Bcast(r2Bcast)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA keygen: marshal FROST Round2 bcast: %w", err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoFrostDKG,
		Round:      FrostDKGRound2,
		FromNodeID: s.session.nodeID,
		Payload:    r2Bytes,
	})

	if ready {
		go s.persistAndFinish()
	}
}

func (s *eddsaKeygenSession) persistAndFinish() {
	vk := s.frostParticipant.VerificationKey
	skShare := s.frostParticipant.SkShare
	vkShare := s.frostParticipant.VkShare

	groupPubKeyBytes := vk.ToAffineCompressed()  // 32 bytes
	vkShareBytes := vkShare.ToAffineCompressed() // 32 bytes
	skShareBytes := skShare.Bytes()              // 32 bytes

	data := &EDDSAKeygenData{
		GroupPublicKey: groupPubKeyBytes,
		NodeIDs:        s.session.peerIDs,
		SkShareBytes:   skShareBytes,
		VkShareBytes:   vkShareBytes,
		Threshold:      s.threshold,
	}
	keyBytes, err := json.Marshal(data)
	if err != nil {
		s.sendErr(fmt.Errorf("EDDSA keygen: marshal output: %w", err))
		return
	}
	defer security.ZeroBytes(keyBytes)

	storageKey := s.session.composeKey(walletIDWithVersion(s.session.walletID, s.session.GetVersion()))
	if err := s.session.kvstore.Put(storageKey, keyBytes); err != nil {
		s.sendErr(fmt.Errorf("EDDSA keygen: persist: %w", err))
		return
	}

	ki := keyinfo.KeyInfo{
		ParticipantPeerIDs: s.session.peerIDs,
		Threshold:          s.threshold,
		Version:            s.session.GetVersion(),
	}
	if err := s.session.keyinfoStore.Save(s.session.composeKey(s.session.walletID), &ki); err != nil {
		s.sendErr(fmt.Errorf("EDDSA keygen: save keyinfo: %w", err))
		return
	}

	s.session.pubkeyBytes = groupPubKeyBytes
	logger.Info("[EDDSA Keygen] Key generation complete", "walletID", s.session.walletID)

	if err := s.Close(); err != nil {
		logger.Error("EDDSA keygen: close session", err)
	}
	if s.done != nil {
		s.done()
	}
}
