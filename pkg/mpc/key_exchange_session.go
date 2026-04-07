package mpc

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"

	"fmt"
	"time"

	"github.com/keyzon-technologies/mpcinfra/pkg/identity"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/keyzon-technologies/mpcinfra/pkg/messaging"
	"github.com/keyzon-technologies/mpcinfra/pkg/types"

	"encoding/json"

	"github.com/nats-io/nats.go"
)

const (
	ECDHExchangeTopic   = "ecdh:exchange"
	ECDHExchangeTimeout = 2 * time.Minute

	// ecdhTimestampWindow is the maximum age (and future skew) accepted for an
	// ECDH broadcast. It must be larger than ECDHExchangeTimeout to accommodate
	// clock differences between nodes, but small enough to block replays from
	// previous sessions.
	ecdhTimestampWindow = 5 * time.Minute
)

type ECDHSession interface {
	ListenKeyExchange() error
	BroadcastPublicKey() error
	RemovePeer(peerID string)
	GetReadyPeersCount() int
	ErrChan() <-chan error
	Close() error
	OnKeyExchangeComplete(callback func())
}

type ecdhSession struct {
	nodeID                string
	peerIDs               []string
	pubSub                messaging.PubSub
	ecdhSub               messaging.Subscription
	identityStore         identity.Store
	privateKey            *ecdh.PrivateKey
	publicKey             *ecdh.PublicKey
	errCh                 chan error
	onKeyExchangeComplete func()
}

func NewECDHSession(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	identityStore identity.Store,
) *ecdhSession {
	logger.Info("Creating ECDH session", "nodeID", nodeID, "peerIDs", peerIDs, "expectedKeys", len(peerIDs))
	return &ecdhSession{
		nodeID:        nodeID,
		peerIDs:       peerIDs,
		pubSub:        pubSub,
		identityStore: identityStore,
		errCh:         make(chan error, 1),
	}
}

func (e *ecdhSession) RemovePeer(peerID string) {
	e.identityStore.RemoveSymmetricKey(peerID)
}

func (e *ecdhSession) GetReadyPeersCount() int {
	return e.identityStore.GetSymetricKeyCount()
}

func (e *ecdhSession) ErrChan() <-chan error {
	return e.errCh
}

func (e *ecdhSession) OnKeyExchangeComplete(callback func()) {
	e.onKeyExchangeComplete = callback
}

func (e *ecdhSession) ListenKeyExchange() error {
	// Generate an ephemeral ECDH key pair
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDH key pair: %w", err)
	}

	e.privateKey = privateKey
	e.publicKey = privateKey.PublicKey()

	// Subscribe to ECDH broadcast
	sub, err := e.pubSub.Subscribe(ECDHExchangeTopic, func(natMsg *nats.Msg) {
		var ecdhMsg types.ECDHMessage
		if err := json.Unmarshal(natMsg.Data, &ecdhMsg); err != nil {
			logger.Error("Failed to unmarshal ECDH message", err)
			return
		}

		if ecdhMsg.From == e.nodeID {
			return
		}

		logger.Debug("Received ECDH message", "from", ecdhMsg.From, "to", e.nodeID)

		if err := e.identityStore.VerifySignature(&ecdhMsg); err != nil {
			logger.Error("ECDH signature verification failed", err, "from", ecdhMsg.From)
			e.errCh <- err
			return
		}

		// Reject messages outside the acceptable time window. Because the
		// timestamp is covered by the Ed25519 signature (MarshalForSigning
		// includes it), an attacker cannot alter it without invalidating the
		// signature. This prevents replay of ECDH broadcasts from previous
		// sessions, which would cause symmetric-key mismatch and break all
		// subsequent P2P message decryption.
		now := time.Now().UTC()
		if ecdhMsg.Timestamp.After(now.Add(ecdhTimestampWindow)) {
			logger.Error("ECDH message timestamp too far in future", fmt.Errorf("skew too large"), "from", ecdhMsg.From)
			e.errCh <- fmt.Errorf("ECDH message from %s has timestamp too far in the future", ecdhMsg.From)
			return
		}
		if ecdhMsg.Timestamp.Before(now.Add(-ecdhTimestampWindow)) {
			logger.Error("ECDH message timestamp expired", fmt.Errorf("message too old"), "from", ecdhMsg.From)
			e.errCh <- fmt.Errorf("ECDH message from %s has expired timestamp (possible replay)", ecdhMsg.From)
			return
		}

		peerPublicKey, err := ecdh.X25519().NewPublicKey(ecdhMsg.PublicKey)
		if err != nil {
			e.errCh <- err
			return
		}
		sharedSecret, err := e.privateKey.ECDH(peerPublicKey)
		if err != nil {
			e.errCh <- err
			return
		}

		// Derive symmetric key using HKDF
		symmetricKey := e.deriveSymmetricKey(sharedSecret, ecdhMsg.From)
		e.identityStore.SetSymmetricKey(ecdhMsg.From, symmetricKey)

		currentKeyCount := e.identityStore.GetSymetricKeyCount()
		logger.Debug("ECDH progress", "peer", ecdhMsg.From, "current", currentKeyCount, "expected", len(e.peerIDs))

		// Check if ECDH exchange is complete and notify callback
		if currentKeyCount == len(e.peerIDs) && e.onKeyExchangeComplete != nil {
			logger.Info("ECDH key exchange completed successfully", "totalKeys", currentKeyCount)
			e.onKeyExchangeComplete()
		}
	})

	e.ecdhSub = sub
	if err != nil {
		return fmt.Errorf("failed to subscribe to ECDH topic: %w", err)
	}
	return nil
}

func (s *ecdhSession) Close() error {
	err := s.ecdhSub.Unsubscribe()
	if err != nil {
		return err
	}

	return nil
}

func (e *ecdhSession) BroadcastPublicKey() error {
	publicKeyBytes := e.publicKey.Bytes()
	msg := types.ECDHMessage{
		From:      e.nodeID,
		PublicKey: publicKeyBytes,
		Timestamp: time.Now(),
	}
	//Sign the message using existing identity store
	signature, err := e.identityStore.SignEcdhMessage(&msg)
	if err != nil {
		return fmt.Errorf("failed to sign ECDH message: %w", err)
	}
	msg.Signature = signature
	signedMsgBytes, _ := json.Marshal(msg)

	logger.Info("Starting to broadcast DH key", "nodeID", e.nodeID)
	if err := e.pubSub.Publish(ECDHExchangeTopic, signedMsgBytes); err != nil {
		return fmt.Errorf("%s failed to publish DH message because %w", e.nodeID, err)
	}
	return nil
}

func deriveConsistentInfo(a, b string) []byte {
	if a < b {
		return []byte(a + b)
	}
	return []byte(b + a)
}

// ecdhHKDFSalt is a fixed, public domain-separation salt for symmetric-key
// derivation. RFC 5869 recommends a non-nil salt when a random one is not
// available; using an application-specific constant prevents cross-protocol
// key-reuse and strengthens derivation against weak shared-secret inputs.
var ecdhHKDFSalt = []byte("mpcinfra-ecdh-symmetric-key-v1")

// derives a symmetric key from the shared secret and peer ID using HKDF.
func (e *ecdhSession) deriveSymmetricKey(sharedSecret []byte, peerID string) []byte {
	hash := sha256.New

	// Info parameter binds the derived key to the specific node pair.
	info := deriveConsistentInfo(e.nodeID, peerID)

	hkdf := hkdf.New(hash, sharedSecret, ecdhHKDFSalt, info)

	// Derive a 32-byte symmetric key (suitable for AES-256)
	symmetricKey := make([]byte, 32)
	_, err := hkdf.Read(symmetricKey)
	if err != nil {
		e.errCh <- err
		return nil
	}
	return symmetricKey
}
