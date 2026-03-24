package mpc

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/core/protocol"
	dklsv2 "github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2"
	"golang.org/x/crypto/sha3"

	"github.com/keyzon-technologies/mpcinfra/pkg/common/errors"
	"github.com/keyzon-technologies/mpcinfra/pkg/event"
	"github.com/keyzon-technologies/mpcinfra/pkg/identity"
	"github.com/keyzon-technologies/mpcinfra/pkg/keyinfo"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/keyzon-technologies/mpcinfra/pkg/messaging"
	"github.com/keyzon-technologies/mpcinfra/pkg/types"
)

// SigningSession is the interface exposed to node.go.
type SigningSession interface {
	Session

	Init(tx *big.Int) error
	Sign(onSuccess func(data []byte))
	WaitForPeersReady() error
	Stop()
	Close() error
}

// ecdsaSigningSession handles a single ECDSA signing request using DKLS19.
// Only two nodes participate (the signing pair chosen by the caller).
type ecdsaSigningSession struct {
	session
	peerNodeID          string // the one peer we sign with
	txID                string
	networkInternalCode string
	derivationPath      []uint32
	ckd                 *CKD
	onSuccess           func([]byte)

	// Populated in Init.
	aliceIter *dklsv2.AliceSign
	bobIter   *dklsv2.BobSign
	isAlice   bool
	msgBytes  []byte // raw tx bytes (passed to hash)

	curve *curves.Curve
}

func newECDSASigningSession(
	walletID string,
	nodeID string,
	peerNodeID string,
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
) *ecdsaSigningSession {
	allPeers := sortNodeIDs([]string{nodeID, peerNodeID})
	return &ecdsaSigningSession{
		session: session{
			walletID:      walletID,
			nodeID:        nodeID,
			peerIDs:       allPeers,
			pubSub:        pubSub,
			direct:        direct,
			ErrCh:         make(chan error, 1),
			doneCh:        make(chan struct{}),
			kvstore:       kvstore,
			keyinfoStore:  keyinfoStore,
			resultQueue:   resultQueue,
			identityStore: identityStore,
			sessionType:   SessionTypeECDSA,
			idempotentKey: idempotentKey,
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("sign:ecdsa:broadcast:%s:%s", walletID, txID)
				},
				ComposeDirectTopic: func(fromID, toID string) string {
					return fmt.Sprintf("sign:ecdsa:direct:%s:%s:%s", fromID, toID, txID)
				},
			},
			composeKey: func(id string) string {
				return fmt.Sprintf("ecdsa:%s", id)
			},
		},
		peerNodeID:          peerNodeID,
		txID:                txID,
		networkInternalCode: networkInternalCode,
		derivationPath:      derivationPath,
		ckd:                 ckd,
		curve:               curves.K256(),
	}
}

// Init loads the DKLS19 pair key and sets up the sign iterators.
func (s *ecdsaSigningSession) Init(tx *big.Int) error {
	s.isAlice = isAlice(s.session.nodeID, s.peerNodeID)
	s.msgBytes = tx.Bytes()

	ki, err := s.session.keyinfoStore.Get(s.session.composeKey(s.session.walletID))
	if err != nil {
		return errors.Wrap(err, "ECDSA sign: load keyinfo")
	}

	rawKey, err := s.session.kvstore.Get(s.session.composeKey(walletIDWithVersion(s.session.walletID, ki.Version)))
	if err != nil {
		return errors.Wrap(err, "ECDSA sign: load key data")
	}

	var kgData ECDSAKeygenData
	if err := json.Unmarshal(rawKey, &kgData); err != nil {
		return errors.Wrap(err, "ECDSA sign: unmarshal key data")
	}

	key := pairKey(s.session.nodeID, s.peerNodeID)
	pairData, ok := kgData.Pairs[key]
	if !ok {
		return fmt.Errorf("ECDSA sign: no pair data for pair %s", key)
	}

	// Derive tweak and child public key if a derivation path is given.
	var (
		tweak    curves.Scalar
		childPub curves.Point
	)
	if len(s.derivationPath) > 0 {
		tweak, childPub, err = s.ckd.DeriveForCurve(s.session.walletID, kgData.GroupPublicKey, s.derivationPath, s.curve)
		if err != nil {
			return fmt.Errorf("ECDSA sign: CKD derive: %w", err)
		}
	}

	hash := sha3.NewLegacyKeccak256()

	if s.isAlice {
		if pairData.AliceMsg == nil {
			return fmt.Errorf("ECDSA sign: missing Alice DKG result for pair %s", key)
		}
		var dkgResult protocol.Message
		if err := json.Unmarshal(pairData.AliceMsg, &dkgResult); err != nil {
			return fmt.Errorf("ECDSA sign: unmarshal Alice DKG result: %w", err)
		}
		if tweak != nil {
			s.aliceIter, err = dklsv2.NewAliceSignWithTweak(s.curve, hash, s.msgBytes, &dkgResult, tweak, childPub, 1)
		} else {
			s.aliceIter, err = dklsv2.NewAliceSign(s.curve, hash, s.msgBytes, &dkgResult, 1)
		}
		if err != nil {
			return fmt.Errorf("ECDSA sign: Alice init: %w", err)
		}
	} else {
		if pairData.BobMsg == nil {
			return fmt.Errorf("ECDSA sign: missing Bob DKG result for pair %s", key)
		}
		var dkgResult protocol.Message
		if err := json.Unmarshal(pairData.BobMsg, &dkgResult); err != nil {
			return fmt.Errorf("ECDSA sign: unmarshal Bob DKG result: %w", err)
		}
		if tweak != nil {
			s.bobIter, err = dklsv2.NewBobSignWithTweak(s.curve, hash, s.msgBytes, &dkgResult, tweak, childPub, 1)
		} else {
			s.bobIter, err = dklsv2.NewBobSign(s.curve, hash, s.msgBytes, &dkgResult, 1)
		}
		if err != nil {
			return fmt.Errorf("ECDSA sign: Bob init: %w", err)
		}
	}

	s.session.version = ki.Version
	return nil
}

func (s *ecdsaSigningSession) ListenToIncomingMessageAsync() {
	s.listenToIncomingMessageAsync(s.onMpcMsg)
}

func (s *ecdsaSigningSession) ListenToPeersAsync(peerIDs []string) {
	s.subscribeFromPeersAsync(peerIDs, s.onMpcMsg)
}

func (s *ecdsaSigningSession) onMpcMsg(msg *types.MpcMsg) {
	if msg.Protocol != types.ProtoDklsSign {
		return
	}
	var protMsg protocol.Message
	if err := json.Unmarshal(msg.Payload, &protMsg); err != nil {
		s.sendErr(fmt.Errorf("ECDSA sign: unmarshal incoming msg: %w", err))
		return
	}

	if s.isAlice {
		// Alice: receive from Bob, reply to Bob.
		reply, err := s.aliceIter.Next(&protMsg)
		if err != nil {
			s.sendErr(fmt.Errorf("ECDSA sign: Alice.Next: %w", err))
			return
		}
		if reply == nil {
			return // Alice is done sending; waits for Bob to finish.
		}
		s.sendSignMsg(reply)
	} else {
		// Bob: receive from Alice, reply or finish.
		reply, err := s.bobIter.Next(&protMsg)
		if err != nil {
			s.sendErr(fmt.Errorf("ECDSA sign: Bob.Next: %w", err))
			return
		}
		if reply == nil {
			// Bob has finished; retrieve and publish the signature.
			s.finishSign()
			return
		}
		s.sendSignMsg(reply)
	}
}

// Sign kicks off the signing protocol. Alice sends the first message.
func (s *ecdsaSigningSession) Sign(onSuccess func(data []byte)) {
	s.onSuccess = onSuccess

	if !s.isAlice {
		// Bob waits for Alice's first message via onMpcMsg.
		return
	}

	// Alice initiates with Round1 (nil input).
	first, err := s.aliceIter.Next(nil)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA sign: Alice Round1: %w", err))
		return
	}
	if first == nil {
		return
	}
	s.sendSignMsg(first)
}

func (s *ecdsaSigningSession) sendSignMsg(msg *protocol.Message) {
	b, err := json.Marshal(msg)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA sign: marshal msg: %w", err))
		return
	}
	s.sendMpcMsg(&types.MpcMsg{
		WalletID:   s.session.walletID,
		Protocol:   types.ProtoDklsSign,
		FromNodeID: s.session.nodeID,
		ToNodeID:   s.peerNodeID,
		Payload:    b,
	})
}

// finishSign is called by Bob when the protocol completes.
func (s *ecdsaSigningSession) finishSign() {
	resultMsg, err := s.bobIter.Result(1)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA sign: Bob.Result: %w", err))
		return
	}

	sig, err := dklsv2.DecodeSignature(resultMsg)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA sign: decode signature: %w", err))
		return
	}

	r := event.SigningResultEvent{
		ResultType:          event.ResultTypeSuccess,
		NetworkInternalCode: s.networkInternalCode,
		WalletID:            s.session.walletID,
		TxID:                s.txID,
		R:                   sig.R.Bytes(),
		S:                   sig.S.Bytes(),
	}
	b, err := json.Marshal(r)
	if err != nil {
		s.sendErr(fmt.Errorf("ECDSA sign: marshal result: %w", err))
		return
	}
	if err := s.session.resultQueue.Enqueue(event.SigningResultCompleteTopic, b, &messaging.EnqueueOptions{
		IdempotententKey: s.session.idempotentKey,
	}); err != nil {
		s.sendErr(fmt.Errorf("ECDSA sign: enqueue result: %w", err))
		return
	}

	logger.Info("[ECDSA Sign] Signature produced", "walletID", s.session.walletID, "txID", s.txID)
	if err := s.Close(); err != nil {
		logger.Error("ECDSA sign: close session", err)
	}
	if s.onSuccess != nil {
		s.onSuccess(b)
	}
}

func (s *ecdsaSigningSession) Close() error {
	for i := range s.derivationPath {
		s.derivationPath[i] = 0
	}
	s.derivationPath = nil
	s.ckd = nil
	return s.session.Close()
}
