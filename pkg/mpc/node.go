package mpc

import (
	"fmt"
	"slices"
	"time"

	"github.com/keyzon-technologies/mpcinfra/pkg/common/errors"
	"github.com/keyzon-technologies/mpcinfra/pkg/identity"
	"github.com/keyzon-technologies/mpcinfra/pkg/keyinfo"
	"github.com/keyzon-technologies/mpcinfra/pkg/kvstore"
	"github.com/keyzon-technologies/mpcinfra/pkg/logger"
	"github.com/keyzon-technologies/mpcinfra/pkg/messaging"
)

const (
	PurposeKeygen  string = "keygen"
	PurposeSign    string = "sign"
	PurposeReshare string = "reshare"

	BackwardCompatibleVersion int = 0
	DefaultVersion            int = 1
)

type ID string

type Node struct {
	nodeID  string
	peerIDs []string

	pubSub        messaging.PubSub
	direct        messaging.DirectMessaging
	kvstore       kvstore.KVStore
	keyinfoStore  keyinfo.Store
	identityStore identity.Store
	peerRegistry  PeerRegistry
	ckd           *CKD
}

func NewNode(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	peerRegistry PeerRegistry,
	identityStore identity.Store,
	ckd *CKD,
) *Node {
	start := time.Now()
	logger.Info("Starting new node", "elapsed_ms", time.Since(start).Milliseconds())

	node := &Node{
		nodeID:        nodeID,
		peerIDs:       peerIDs,
		pubSub:        pubSub,
		direct:        direct,
		kvstore:       kvstore,
		keyinfoStore:  keyinfoStore,
		peerRegistry:  peerRegistry,
		identityStore: identityStore,
		ckd:           ckd,
	}

	go peerRegistry.WatchPeersReady()
	return node
}

func (p *Node) ID() string {
	return p.nodeID
}

func (p *Node) CreateKeyGenSession(
	sessionType SessionType,
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (KeyGenSession, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, errors.New("All nodes are not ready!")
	}

	keyInfo, _ := p.getKeyInfo(sessionType, walletID)
	if keyInfo != nil {
		return nil, fmt.Errorf("Key already exists: %s", walletID)
	}

	switch sessionType {
	case SessionTypeECDSA:
		return p.createECDSAKeyGenSession(walletID, threshold, resultQueue)
	case SessionTypeEDDSA:
		return p.createEDDSAKeyGenSession(walletID, threshold, resultQueue)
	default:
		return nil, fmt.Errorf("Unknown session type: %s", sessionType)
	}
}

func (p *Node) createECDSAKeyGenSession(walletID string, threshold int, resultQueue messaging.MessageQueue) (KeyGenSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	sorted := sortNodeIDs(readyPeerIDs)
	return newECDSAKeygenSession(
		walletID,
		p.nodeID,
		sorted,
		threshold,
		p.pubSub,
		p.direct,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	), nil
}

func (p *Node) createEDDSAKeyGenSession(walletID string, threshold int, resultQueue messaging.MessageQueue) (KeyGenSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	sorted := sortNodeIDs(readyPeerIDs)
	return newEDDSAKeygenSession(
		walletID,
		p.nodeID,
		sorted,
		threshold,
		p.pubSub,
		p.direct,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	), nil
}

func (p *Node) CreateSigningSession(
	sessionType SessionType,
	walletID string,
	txID string,
	networkInternalCode string,
	resultQueue messaging.MessageQueue,
	derivationPath []uint32,
	idempotentKey string,
) (SigningSession, error) {
	keyInfo, err := p.getKeyInfo(sessionType, walletID)
	if err != nil {
		return nil, err
	}

	readyPeers := p.peerRegistry.GetReadyPeersIncludeSelf()
	readyParticipantIDs := p.getReadyPeersForSession(keyInfo, readyPeers)

	logger.Info("Creating signing session",
		"type", sessionType,
		"readyPeers", readyPeers,
		"participantPeerIDs", keyInfo.ParticipantPeerIDs,
		"readyCount", len(readyParticipantIDs),
		"minReady", keyInfo.Threshold+1,
	)

	if len(readyParticipantIDs) < keyInfo.Threshold+1 {
		return nil, fmt.Errorf("not enough peers to create signing session! expected %d, got %d", keyInfo.Threshold+1, len(readyParticipantIDs))
	}

	if err := p.ensureNodeIsParticipant(keyInfo); err != nil {
		return nil, err
	}

	switch sessionType {
	case SessionTypeECDSA:
		// DKLS19 is a 2-party protocol: pick any one ready signing peer.
		peerNodeID := ""
		sortedReady := sortNodeIDs(readyParticipantIDs)
		for _, id := range sortedReady {
			if id != p.nodeID {
				peerNodeID = id
				break
			}
		}
		if peerNodeID == "" {
			return nil, errors.New("ECDSA sign: no ready peer available")
		}
		return newECDSASigningSession(
			walletID,
			p.nodeID,
			peerNodeID,
			txID,
			networkInternalCode,
			p.pubSub,
			p.direct,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			derivationPath,
			idempotentKey,
			p.ckd,
		), nil

	case SessionTypeEDDSA:
		// FROST signing: all t+1 ready participants sign together.
		sorted := sortNodeIDs(readyParticipantIDs)
		return newEDDSASigningSession(
			walletID,
			p.nodeID,
			sorted,
			txID,
			networkInternalCode,
			p.pubSub,
			p.direct,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			derivationPath,
			idempotentKey,
			p.ckd,
		), nil
	}

	return nil, errors.New("unknown session type")
}

func (p *Node) getKeyInfo(sessionType SessionType, walletID string) (*keyinfo.KeyInfo, error) {
	var keyID string
	switch sessionType {
	case SessionTypeECDSA:
		keyID = fmt.Sprintf("ecdsa:%s", walletID)
	case SessionTypeEDDSA:
		keyID = fmt.Sprintf("eddsa:%s", walletID)
	default:
		return nil, errors.New("unsupported session type")
	}
	return p.keyinfoStore.Get(keyID)
}

func (p *Node) getReadyPeersForSession(keyInfo *keyinfo.KeyInfo, readyPeers []string) []string {
	readyParticipantIDs := make([]string, 0, len(keyInfo.ParticipantPeerIDs))
	for _, peerID := range keyInfo.ParticipantPeerIDs {
		if slices.Contains(readyPeers, peerID) {
			readyParticipantIDs = append(readyParticipantIDs, peerID)
		}
	}
	return readyParticipantIDs
}

func (p *Node) ensureNodeIsParticipant(keyInfo *keyinfo.KeyInfo) error {
	if !slices.Contains(keyInfo.ParticipantPeerIDs, p.nodeID) {
		return ErrNotInParticipantList
	}
	return nil
}

func (p *Node) CreateReshareSession(
	sessionType SessionType,
	walletID string,
	newThreshold int,
	newPeerIDs []string,
	isNewPeer bool,
	resultQueue messaging.MessageQueue,
) (ReshareSession, error) {
	count := p.peerRegistry.GetReadyPeersCount()
	if count < int64(newThreshold)+1 {
		return nil, fmt.Errorf(
			"not enough peers to create reshare session! Expected at least %d, got %d",
			newThreshold+1,
			count,
		)
	}

	if len(newPeerIDs) < newThreshold+1 {
		return nil, fmt.Errorf("new peer list is smaller than required t+1")
	}

	// Verify all new peers are ready.
	readyNewPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	for _, peerID := range newPeerIDs {
		if !slices.Contains(readyNewPeerIDs, peerID) {
			return nil, fmt.Errorf("new peer %s is not ready", peerID)
		}
	}

	// Load old key info.
	keyPrefix, err := sessionKeyPrefix(sessionType)
	if err != nil {
		return nil, fmt.Errorf("failed to get session key prefix: %w", err)
	}
	keyInfoKey := fmt.Sprintf("%s:%s", keyPrefix, walletID)
	oldKeyInfo, err := p.keyinfoStore.Get(keyInfoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get old key info: %w", err)
	}

	readyPeers := p.peerRegistry.GetReadyPeersIncludeSelf()
	readyOldParticipantIDs := p.getReadyPeersForSession(oldKeyInfo, readyPeers)

	isInOldCommittee := slices.Contains(oldKeyInfo.ParticipantPeerIDs, p.nodeID)
	isInNewCommittee := slices.Contains(newPeerIDs, p.nodeID)

	if isNewPeer && !isInNewCommittee {
		logger.Info("Skipping: node is not in new committee", "walletID", walletID, "nodeID", p.nodeID)
		return nil, nil
	}
	if !isNewPeer && !isInOldCommittee {
		logger.Info("Skipping: node is not in old committee", "walletID", walletID, "nodeID", p.nodeID)
		return nil, nil
	}

	logger.Info("Creating resharing session",
		"type", sessionType,
		"readyPeers", readyPeers,
		"participantPeerIDs", oldKeyInfo.ParticipantPeerIDs,
		"readyCount", len(readyOldParticipantIDs),
		"minReady", oldKeyInfo.Threshold+1,
		"version", oldKeyInfo.Version,
		"isNewPeer", isNewPeer,
	)

	if len(readyOldParticipantIDs) < oldKeyInfo.Threshold+1 {
		return nil, fmt.Errorf("not enough peers to create resharing session! expected %d, got %d", oldKeyInfo.Threshold+1, len(readyOldParticipantIDs))
	}

	if !isNewPeer {
		if err := p.ensureNodeIsParticipant(oldKeyInfo); err != nil {
			return nil, err
		}
	}

	oldPeerIDs := sortNodeIDs(oldKeyInfo.ParticipantPeerIDs)
	sortedNewPeerIDs := sortNodeIDs(newPeerIDs)

	switch sessionType {
	case SessionTypeECDSA:
		return NewECDSAReshareSession(
			walletID,
			p.nodeID,
			oldPeerIDs,
			sortedNewPeerIDs,
			oldKeyInfo.Threshold,
			newThreshold,
			p.pubSub,
			p.direct,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			isNewPeer,
			oldKeyInfo.Version,
		), nil

	case SessionTypeEDDSA:
		return NewEDDSAReshareSession(
			walletID,
			p.nodeID,
			oldPeerIDs,
			sortedNewPeerIDs,
			oldKeyInfo.Threshold,
			newThreshold,
			p.pubSub,
			p.direct,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
			isNewPeer,
			oldKeyInfo.Version,
		), nil

	default:
		return nil, fmt.Errorf("unsupported session type: %v", sessionType)
	}
}

func ComposeReadyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func (p *Node) Close() {
	if err := p.peerRegistry.Resign(); err != nil {
		logger.Error("Resign failed", err)
	}
}

func (p *Node) getVersion(sessionType SessionType, walletID string) int {
	var composeKey string
	switch sessionType {
	case SessionTypeECDSA:
		composeKey = fmt.Sprintf("ecdsa:%s", walletID)
	case SessionTypeEDDSA:
		composeKey = fmt.Sprintf("eddsa:%s", walletID)
	default:
		logger.Fatal("Unknown session type", errors.New("Unknown session type"))
	}
	ki, err := p.keyinfoStore.Get(composeKey)
	if err != nil {
		logger.Error("Get keyinfo failed", err, "walletID", walletID)
		return DefaultVersion
	}
	return ki.Version
}

func sessionKeyPrefix(sessionType SessionType) (string, error) {
	switch sessionType {
	case SessionTypeECDSA:
		return "ecdsa", nil
	case SessionTypeEDDSA:
		return "eddsa", nil
	default:
		return "", fmt.Errorf("unsupported session type: %v", sessionType)
	}
}
