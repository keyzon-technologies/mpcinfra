package mpc

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/keyzon-technologies/mpcinfra/pkg/common/errors"
	"github.com/keyzon-technologies/mpcinfra/pkg/identity"
	"github.com/keyzon-technologies/mpcinfra/pkg/keyinfo"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/keyzon-technologies/mpcinfra/pkg/messaging"
	"github.com/keyzon-technologies/mpcinfra/pkg/types"
	"github.com/nats-io/nats.go"
)

type SessionType string

const (
	TypeGenerateWalletResultFmt = "mpc.mpc_keygen_result.%s"
	TypeReshareWalletResultFmt  = "mpc.mpc_reshare_result.%s"
	TypeSigningResultFmt        = "mpc.mpc_signing_result.%s"

	SessionTypeECDSA SessionType = "session_ecdsa"
	SessionTypeEDDSA SessionType = "session_eddsa"

	// PeerReadyTimeout is the max time to wait for all peers to confirm
	// their subscriptions are active before starting the protocol.
	PeerReadyTimeout = 10 * time.Second
	// PeerReadyPollInterval is how often to retry the readiness check.
	PeerReadyPollInterval = 300 * time.Millisecond
)

var (
	ErrNotEnoughParticipants = errors.New("Not enough participants to sign")
	ErrNotInParticipantList  = errors.New("Node is not in the participant list")
)

type TopicComposer struct {
	ComposeBroadcastTopic func() string
	ComposeDirectTopic    func(fromID string, toID string) string
}

type KeyComposerFn func(id string) string

type Session interface {
	ListenToIncomingMessageAsync()
	ListenToPeersAsync(peerIDs []string)
	ErrChan() <-chan error
}

// session is the base struct shared by all MPC session types.
// It manages NATS subscriptions, peer readiness barriers, and message
// routing using MpcMsg — no tss-lib types.
type session struct {
	walletID string
	nodeID   string   // self node ID
	peerIDs  []string // all peer IDs including self, sorted lexicographically

	pubSub  messaging.PubSub
	direct  messaging.DirectMessaging
	version int

	kvstore       kvstore.KVStore
	keyinfoStore  keyinfo.Store
	identityStore identity.Store

	broadcastSub messaging.Subscription
	directSubs   []messaging.Subscription
	barrierSub   messaging.Subscription

	resultQueue   messaging.MessageQueue
	topicComposer *TopicComposer
	composeKey    KeyComposerFn

	ErrCh     chan error
	doneCh    chan struct{}
	doneOnce  sync.Once
	closeOnce sync.Once
	mu        sync.Mutex

	pubkeyBytes   []byte
	sessionType   SessionType
	idempotentKey string
}

// sendErr sends an error to ErrCh without blocking if the session is stopped.
func (s *session) sendErr(err error) {
	select {
	case s.ErrCh <- err:
	case <-s.doneCh:
	}
}

// Stop signals the session to terminate. Safe to call multiple times.
func (s *session) Stop() {
	s.doneOnce.Do(func() {
		close(s.doneCh)
	})
}

// Done returns a channel that is closed when the session should stop.
func (s *session) Done() <-chan struct{} {
	return s.doneCh
}

// sendMpcMsg sends an MpcMsg to one peer (point-to-point) or broadcasts it.
// isBroadcast = true sends to all peers on the broadcast topic (with signature).
// isBroadcast = false sends encrypted directly to toNodeID.
func (s *session) sendMpcMsg(msg *types.MpcMsg) {
	if msg.ToNodeID == "" {
		// Empty ToNodeID means broadcast to all peers.
		signature, err := s.identityStore.SignMessage(msg)
		if err != nil {
			s.sendErr(fmt.Errorf("failed to sign message: %w", err))
			return
		}
		msg.Signature = signature
		raw, err := types.MarshalMpcMsg(msg)
		if err != nil {
			s.sendErr(fmt.Errorf("failed to marshal mpc message: %w", err))
			return
		}
		if err := s.pubSub.Publish(s.topicComposer.ComposeBroadcastTopic(), raw); err != nil {
			s.sendErr(err)
		}
		return
	}

	// Point-to-point (ToNodeID is set)
	raw, err := types.MarshalMpcMsg(msg)
	if err != nil {
		s.sendErr(fmt.Errorf("failed to marshal mpc message: %w", err))
		return
	}

	toID := msg.ToNodeID
	topic := s.topicComposer.ComposeDirectTopic(s.nodeID, toID)
	if toID == s.nodeID {
		if err := s.direct.SendToSelf(topic, raw); err != nil {
			logger.Error("Failed SendToSelf", err, "topic", topic)
			s.sendErr(fmt.Errorf("failed to send direct message to %s: %w", topic, err))
		}
		return
	}
	cipher, err := s.identityStore.EncryptMessage(raw, toID)
	if err != nil {
		s.sendErr(fmt.Errorf("encrypt mpc message error: %w", err))
		return
	}
	if err := s.direct.SendToOther(topic, cipher); err != nil {
		logger.Error("Failed SendToOther", err, "topic", topic)
		s.sendErr(fmt.Errorf("failed to send direct message: %w", err))
	}
}

// receiveP2PMpcMessage decrypts and dispatches a direct (p2p) NATS message.
// Subclasses provide a handler via the onMpcMsg callback.
func (s *session) receiveP2PMpcMessage(topic string, cipher []byte, onMpcMsg func(*types.MpcMsg)) {
	senderID := extractSenderIDFromDirectTopic(topic)
	if senderID == "" {
		s.sendErr(fmt.Errorf("failed to extract senderID from direct topic: %s", topic))
		return
	}

	var plaintext []byte
	if senderID == s.nodeID {
		plaintext = cipher // loopback message, no decryption
	} else {
		var err error
		plaintext, err = s.identityStore.DecryptMessage(cipher, senderID)
		if err != nil {
			s.sendErr(fmt.Errorf("failed to decrypt message from %s: %w", senderID, err))
			return
		}
	}

	msg, err := types.UnmarshalMpcMsg(plaintext)
	if err != nil {
		s.sendErr(fmt.Errorf("failed to unmarshal mpc message: %w", err))
		return
	}

	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in receiveP2PMpcMessage",
				fmt.Errorf("%v", r), "walletID", s.walletID,
				"stack", string(debug.Stack()))
			s.ErrCh <- fmt.Errorf("panic in receiveP2PMpcMessage: %v", r)
		}
	}()
	onMpcMsg(msg)
}

// receiveBroadcastMpcMessage verifies and dispatches a broadcast NATS message.
func (s *session) receiveBroadcastMpcMessage(rawMsg []byte, onMpcMsg func(*types.MpcMsg)) {
	msg, err := types.UnmarshalMpcMsg(rawMsg)
	if err != nil {
		s.sendErr(fmt.Errorf("failed to unmarshal broadcast message: %w", err))
		return
	}
	if err := s.identityStore.VerifyMessage(msg); err != nil {
		s.sendErr(fmt.Errorf("failed to verify broadcast message: %w", err))
		return
	}

	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in receiveBroadcastMpcMessage",
				fmt.Errorf("%v", r), "walletID", s.walletID,
				"stack", string(debug.Stack()))
			s.ErrCh <- fmt.Errorf("panic in receiveBroadcastMpcMessage: %v", r)
		}
	}()
	onMpcMsg(msg)
}

func (s *session) subscribeDirectTopicAsync(topic string, onMpcMsg func(*types.MpcMsg)) error {
	t := topic
	sub, err := s.direct.Listen(t, func(cipher []byte) {
		go s.receiveP2PMpcMessage(t, cipher, onMpcMsg)
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to direct topic %s: %w", t, err)
	}
	s.directSubs = append(s.directSubs, sub)
	return nil
}

func (s *session) subscribeFromPeersAsync(fromIDs []string, onMpcMsg func(*types.MpcMsg)) {
	toID := s.nodeID
	for _, fromID := range fromIDs {
		topic := s.topicComposer.ComposeDirectTopic(fromID, toID)
		if err := s.subscribeDirectTopicAsync(topic, onMpcMsg); err != nil {
			s.sendErr(err)
		}
	}
}

func (s *session) subscribeBroadcastAsync(onMpcMsg func(*types.MpcMsg)) {
	go func() {
		topic := s.topicComposer.ComposeBroadcastTopic()
		sub, err := s.pubSub.Subscribe(topic, func(natMsg *nats.Msg) {
			s.receiveBroadcastMpcMessage(natMsg.Data, onMpcMsg)
		})
		if err != nil {
			s.sendErr(fmt.Errorf("failed to subscribe to broadcast topic %s: %w", topic, err))
			return
		}
		s.mu.Lock()
		s.broadcastSub = sub
		s.mu.Unlock()
	}()
}

// ListenToIncomingMessageAsync starts broadcast and direct subscriptions.
// Subclasses call this with their own onMpcMsg handler.
func (s *session) listenToIncomingMessageAsync(onMpcMsg func(*types.MpcMsg)) {
	s.subscribeBroadcastAsync(onMpcMsg)
	s.subscribeFromPeersAsync(s.peerIDs, onMpcMsg)
}

// ListenToIncomingMessageAsync implements Session (uses a no-op handler; subclasses override).
func (s *session) ListenToIncomingMessageAsync() {
	// No-op default; specific sessions override by calling listenToIncomingMessageAsync
	// with their own onMpcMsg dispatch function.
}

// ListenToPeersAsync subscribes to direct messages from the given peer IDs.
func (s *session) ListenToPeersAsync(peerIDs []string) {
	// No-op default; specific sessions override.
}

// WaitForPeersReady subscribes to a session-specific barrier topic, then verifies each peer has its barrier
// subscription active by sending NATS requests. This guarantees all peers
// have their direct-message subscriptions set up before the protocol starts.
func (s *session) WaitForPeersReady() error {
	selfID := s.nodeID
	barrierTopic := fmt.Sprintf("barrier:%s:%s", s.topicComposer.ComposeBroadcastTopic(), selfID)

	sub, err := s.direct.Listen(barrierTopic, func([]byte) {})
	if err != nil {
		return fmt.Errorf("failed to subscribe to barrier topic: %w", err)
	}
	s.barrierSub = sub

	deadline := time.After(PeerReadyTimeout)
	for _, peerID := range s.peerIDs {
		if peerID == selfID {
			continue
		}
		peerBarrier := fmt.Sprintf("barrier:%s:%s", s.topicComposer.ComposeBroadcastTopic(), peerID)

		for {
			err := s.direct.SendToOtherWithRetry(peerBarrier, []byte("ready"), messaging.RetryConfig{
				RetryAttempt: 1,
				Delay:        PeerReadyPollInterval,
			})
			if err == nil {
				logger.Debug("Peer ready", "peerID", peerID, "session", s.sessionType)
				break
			}

			select {
			case <-deadline:
				return fmt.Errorf("timeout waiting for peer %s to be ready", peerID)
			case <-s.doneCh:
				return fmt.Errorf("session stopped while waiting for peers")
			default:
				time.Sleep(PeerReadyPollInterval)
			}
		}
	}

	logger.Info("All peers ready", "session", s.sessionType, "walletID", s.walletID)
	return nil
}

func (s *session) Close() error {
	s.Stop()

	s.closeOnce.Do(func() {
		if s.barrierSub != nil {
			if err := s.barrierSub.Unsubscribe(); err != nil {
				logger.Error("Failed to unsubscribe barrier", err)
			}
		}
		s.mu.Lock()
		broadcastSub := s.broadcastSub
		s.mu.Unlock()
		if broadcastSub != nil {
			if err := broadcastSub.Unsubscribe(); err != nil {
				logger.Error("Failed to unsubscribe broadcast", err)
			}
		}
		for _, sub := range s.directSubs {
			if err := sub.Unsubscribe(); err != nil {
				logger.Error("Failed to unsubscribe direct", err)
			}
		}
	})
	return nil
}

func (s *session) GetPubKeyResult() []byte {
	return s.pubkeyBytes
}

func (s *session) ErrChan() <-chan error {
	return s.ErrCh
}

func (s *session) GetVersion() int {
	return s.version
}

// loadOldShareDataGeneric loads share data from kvstore with backward-compatible versioned key fallback.
func (s *session) loadOldShareDataGeneric(walletID string, version int, dest any) error {
	var (
		key     string
		keyData []byte
		err     error
	)

	if version > 0 {
		key = s.composeKey(walletIDWithVersion(walletID, version))
		keyData, err = s.kvstore.Get(key)
		if err != nil {
			return err
		}
	}

	if version == 0 {
		key = s.composeKey(walletID)
		keyData, err = s.kvstore.Get(key)
		if err != nil {
			return err
		}
	}

	if err != nil {
		return fmt.Errorf("failed to get wallet data from KVStore (key=%s): %w", key, err)
	}

	if err := json.Unmarshal(keyData, dest); err != nil {
		return fmt.Errorf("failed to unmarshal wallet data: %w", err)
	}
	return nil
}

func walletIDWithVersion(walletID string, version int) string {
	if version > 0 {
		return fmt.Sprintf("%s_v%d", walletID, version)
	}
	return walletID
}

func extractSenderIDFromDirectTopic(topic string) string {
	// E.g: keygen:direct:ecdsa:<fromID>:<toID>:<walletID>
	parts := strings.SplitN(topic, ":", 5)
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}
