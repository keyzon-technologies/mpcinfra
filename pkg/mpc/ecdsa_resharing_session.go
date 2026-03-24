package mpc

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/core/protocol"
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

// ReshareSession is the interface exposed to node.go.
type ReshareSession interface {
	Session
	Init() error
	Reshare(done func())
	GetPubKeyResult() []byte
	GetLegacyCommitteePeers() []string
	WaitForPeersReady() error
	Stop()
}

// ecdsaReshareSession implements proactive key refresh for DKLS19.
//
// Each pair {alice, bob} that exists in the new committee runs the DKLS19
// Refresh protocol: Alice's share decreases by k, Bob's share increases by k,
// preserving the joint secret x = sk_A + sk_B. The group public key is unchanged.
//
// The old committee peers are the ones with the current Shamir shares.
// New peers that weren't in the old committee start with zero shares (not yet supported —
// full committee rotation requires a separate FROST re-sharing DKG).
type ecdsaReshareSession struct {
	session
	oldThreshold int
	newThreshold int
	oldPeerIDs   []string // old committee peers (sorted)
	newPeerIDs   []string // new committee peers (sorted)
	isNewPeer    bool

	// Pair refresh iterators for all pairs this node participates in.
	aliceIterators map[string]*dklsv2.AliceRefresh // pairKey → Alice iterator
	bobIterators   map[string]*dklsv2.BobRefresh   // pairKey → Bob iterator
	pairsMu        sync.Mutex
	pairMutexes    map[string]*sync.Mutex
	pairsComplete  map[string]bool
	persistOnce    sync.Once
	pairsStarted   atomic.Bool
	done           func()

	curve *curves.Curve
}

// NewECDSAReshareSession constructs an ECDSA refresh session.
// All members of the new committee must call this; old-committee-only members may skip.
func NewECDSAReshareSession(
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
) *ecdsaReshareSession {
	activePeerIDs := oldPeerIDs
	if isNewPeer {
		activePeerIDs = newPeerIDs
	}
	return &ecdsaReshareSession{
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
			sessionType:   SessionTypeECDSA,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("resharing:broadcast:ecdsa:%s", walletID)
				},
				ComposeDirectTopic: func(fromID, toID string) string {
					return fmt.Sprintf("resharing:direct:ecdsa:%s:%s:%s", fromID, toID, walletID)
				},
			},
			composeKey: func(id string) string {
				return fmt.Sprintf("ecdsa:%s", id)
			},
		},
		oldThreshold:   oldThreshold,
		newThreshold:   newThreshold,
		oldPeerIDs:     oldPeerIDs,
		newPeerIDs:     newPeerIDs,
		isNewPeer:      isNewPeer,
		aliceIterators: make(map[string]*dklsv2.AliceRefresh),
		bobIterators:   make(map[string]*dklsv2.BobRefresh),
		pairMutexes:    make(map[string]*sync.Mutex),
		pairsComplete:  make(map[string]bool),
		curve:          curves.K256(),
	}
}

// GetLegacyCommitteePeers returns peers that were in the old committee but not the new one.
func (s *ecdsaReshareSession) GetLegacyCommitteePeers() []string {
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

func (s *ecdsaReshareSession) Init() error {
	// Load current keygen data.
	rawKey, err := s.session.kvstore.Get(s.session.composeKey(walletIDWithVersion(s.session.walletID, s.session.GetVersion())))
	if err != nil {
		return fmt.Errorf("ECDSA reshare: load key data: %w", err)
	}
	var kgData ECDSAKeygenData
	if err := json.Unmarshal(rawKey, &kgData); err != nil {
		return fmt.Errorf("ECDSA reshare: unmarshal key data: %w", err)
	}

	// Build refresh iterators for each pair in the new committee that this node participates in.
	n := len(s.newPeerIDs)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			aliceNodeID := s.newPeerIDs[i]
			bobNodeID := s.newPeerIDs[j]
			key := pairKey(aliceNodeID, bobNodeID)

			if s.session.nodeID != aliceNodeID && s.session.nodeID != bobNodeID {
				continue
			}

			pairData, ok := kgData.Pairs[key]
			if !ok {
				return fmt.Errorf("ECDSA reshare: missing pair data for %s", key)
			}

			if s.session.nodeID == aliceNodeID {
				if pairData.AliceMsg == nil {
					return fmt.Errorf("ECDSA reshare: missing Alice data for pair %s", key)
				}
				var dkgResult protocol.Message
				if err := json.Unmarshal(pairData.AliceMsg, &dkgResult); err != nil {
					return fmt.Errorf("ECDSA reshare: unmarshal Alice DKG result: %w", err)
				}
				s.pairMutexes[key] = &sync.Mutex{}
				iter, err := dklsv2.NewAliceRefresh(s.curve, &dkgResult, 1)
				if err != nil {
					return fmt.Errorf("ECDSA reshare: NewAliceRefresh for %s: %w", key, err)
				}
				s.aliceIterators[key] = iter
			} else {
				if pairData.BobMsg == nil {
					return fmt.Errorf("ECDSA reshare: missing Bob data for pair %s", key)
				}
				var dkgResult protocol.Message
				if err := json.Unmarshal(pairData.BobMsg, &dkgResult); err != nil {
					return fmt.Errorf("ECDSA reshare: unmarshal Bob DKG result: %w", err)
				}
				s.pairMutexes[key] = &sync.Mutex{}
				iter, err := dklsv2.NewBobRefresh(s.curve, &dkgResult, 1)
				if err != nil {
					return fmt.Errorf("ECDSA reshare: NewBobRefresh for %s: %w", key, err)
				}
				s.bobIterators[key] = iter
			}
		}
	}
	return nil
}

func (s *ecdsaReshareSession) ListenToIncomingMessageAsync() {
	s.listenToIncomingMessageAsync(s.onMpcMsg)
}

func (s *ecdsaReshareSession) ListenToPeersAsync(peerIDs []string) {
	s.subscribeFromPeersAsync(peerIDs, s.onMpcMsg)
}

func (s *ecdsaReshareSession) onMpcMsg(msg *types.MpcMsg) {
	if msg.Protocol != types.ProtoDklsRefresh {
		return
	}
	s.handleRefreshMsg(msg)
}

func (s *ecdsaReshareSession) Reshare(done func()) {
	s.done = done
	if !s.pairsStarted.CompareAndSwap(false, true) {
		return
	}
	// Alice initiates each refresh.
	for key, alice := range s.aliceIterators {
		parts := splitPairKey(key)
		go s.sendRefreshIteratorMsg(key, parts[0], parts[1], alice, nil, parts[1])
	}
}

// splitPairKey splits "alice|bob" into ["alice", "bob"].
func splitPairKey(key string) [2]string {
	for i, c := range key {
		if c == '|' {
			return [2]string{key[:i], key[i+1:]}
		}
	}
	return [2]string{key, ""}
}

func (s *ecdsaReshareSession) sendRefreshIteratorMsg(
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
		s.sendErr(fmt.Errorf("ECDSA reshare pair %s: Next: %w", key, err))
		return
	}
	if reply == nil {
		s.markPairComplete(key)
		return
	}
	b, err := json.Marshal(reply)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA reshare pair %s: marshal reply: %w", key, err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoDklsRefresh,
		PairAlice:  aliceNodeID,
		PairBob:    bobNodeID,
		FromNodeID: s.session.nodeID,
		ToNodeID:   toNodeID,
		Payload:    b,
	})
}

func (s *ecdsaReshareSession) handleRefreshMsg(msg *types.MpcMsg) {
	key := pairKey(msg.PairAlice, msg.PairBob)
	var protMsg protocol.Message
	if err := json.Unmarshal(msg.Payload, &protMsg); err != nil {
		s.sendErr(fmt.Errorf("ECDSA reshare pair %s: unmarshal: %w", key, err))
		return
	}

	if msg.PairAlice == s.session.nodeID {
		alice, ok := s.aliceIterators[key]
		if !ok {
			return
		}
		go s.sendRefreshIteratorMsg(key, msg.PairAlice, msg.PairBob, alice, &protMsg, msg.PairBob)
	} else if msg.PairBob == s.session.nodeID {
		bob, ok := s.bobIterators[key]
		if !ok {
			return
		}
		go s.sendRefreshIteratorMsg(key, msg.PairAlice, msg.PairBob, bob, &protMsg, msg.PairAlice)
	}
}

func (s *ecdsaReshareSession) markPairComplete(key string) {
	s.pairsMu.Lock()
	s.pairsComplete[key] = true
	total := len(s.aliceIterators) + len(s.bobIterators)
	done := len(s.pairsComplete)
	s.pairsMu.Unlock()

	if done >= total {
		s.persistOnce.Do(func() { go s.persistAndFinish() })
	}
}

func (s *ecdsaReshareSession) persistAndFinish() {
	// Load current keygen data to get group public key, node IDs, shamir share.
	rawKey, err := s.session.kvstore.Get(s.session.composeKey(walletIDWithVersion(s.session.walletID, s.session.GetVersion())))
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA reshare: reload key data: %w", err))
		return
	}
	var kgData ECDSAKeygenData
	if err := json.Unmarshal(rawKey, &kgData); err != nil {
		s.sendErr(fmt.Errorf("ECDSA reshare: unmarshal key data: %w", err))
		return
	}

	// Update pair data from refreshed iterators.
	for key, alice := range s.aliceIterators {
		resultMsg, err := alice.Result(1)
		if err != nil {
			s.sendErr(fmt.Errorf("ECDSA reshare pair %s: Alice.Result: %w", key, err))
			return
		}
		b, err := json.Marshal(resultMsg)
		if err != nil {
			s.sendErr(fmt.Errorf("ECDSA reshare pair %s: marshal Alice result: %w", key, err))
			return
		}
		kgData.Pairs[key] = &DklsPairData{AliceMsg: b}
	}
	for key, bob := range s.bobIterators {
		resultMsg, err := bob.Result(1)
		if err != nil {
			s.sendErr(fmt.Errorf("ECDSA reshare pair %s: Bob.Result: %w", key, err))
			return
		}
		b, err := json.Marshal(resultMsg)
		if err != nil {
			s.sendErr(fmt.Errorf("ECDSA reshare pair %s: marshal Bob result: %w", key, err))
			return
		}
		if existing, ok := kgData.Pairs[key]; ok {
			existing.BobMsg = b
		} else {
			kgData.Pairs[key] = &DklsPairData{BobMsg: b}
		}
	}

	// Update node IDs for new committee.
	kgData.NodeIDs = s.newPeerIDs

	// Update shamir share — recompute from the new Alice/Bob shares.
	// (The group public key Q and individual pair shares change; recompute group share
	// from the FROST participant's share which is unchanged in additive refresh.)
	// For now, keep the same ShamirShare since the group secret x = sum(sk_A+sk_B) is preserved.

	newVersion := s.session.GetVersion() + 1
	keyBytes, err := json.Marshal(kgData)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA reshare: marshal refreshed data: %w", err))
		return
	}
	defer security.ZeroBytes(keyBytes)

	storageKey := s.session.composeKey(walletIDWithVersion(s.session.walletID, newVersion))
	if err := s.session.kvstore.Put(storageKey, keyBytes); err != nil {
		s.sendErr(fmt.Errorf("ECDSA reshare: persist: %w", err))
		return
	}

	ki := keyinfo.KeyInfo{
		ParticipantPeerIDs: s.newPeerIDs,
		Threshold:          s.newThreshold,
		Version:            newVersion,
	}
	if err := s.session.keyinfoStore.Save(s.session.composeKey(s.session.walletID), &ki); err != nil {
		s.sendErr(fmt.Errorf("ECDSA reshare: save keyinfo: %w", err))
		return
	}

	// Decode and set public key bytes for the result.
	pubKeyBytes, err := encoding.DecodeECDSAPubKey(append([]byte{0x04}, kgData.GroupPublicKey...))
	if err == nil {
		encoded, err2 := encoding.EncodeS256PubKey(pubKeyBytes)
		if err2 == nil {
			s.session.pubkeyBytes = encoded
		}
	}

	logger.Info("[ECDSA Reshare] Refresh complete", "walletID", s.session.walletID, "newVersion", newVersion)
	if err := s.Close(); err != nil {
		logger.Error("ECDSA reshare: close session", err)
	}

	// Also recompute Lagrange-weighted shares for the new committee composition.
	// (This is needed if the set of signers changes; for same-committee refresh, shares are still valid.)
	// For now, assume same committee after reshare (TODO: full committee rotation with new FROST DKG).
	_ = sharing.ShamirShare{} // placeholder to keep import used until full impl

	if s.done != nil {
		s.done()
	}
}
