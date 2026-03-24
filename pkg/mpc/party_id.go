package mpc

import "sort"

// sortNodeIDs returns a new sorted copy of nodeIDs (lexicographic order).
// The DKLS19 Alice/Bob role is assigned by position: index 0 = Alice.
func sortNodeIDs(nodeIDs []string) []string {
	out := make([]string, len(nodeIDs))
	copy(out, nodeIDs)
	sort.Strings(out)
	return out
}

// isAlice returns true when nodeID is lexicographically less than peerID,
// i.e. nodeID takes the Alice role in the DKLS19 pair {nodeID, peerID}.
func isAlice(nodeID, peerID string) bool {
	return nodeID < peerID
}

// pairKey returns a stable string key for a signing pair, always in
// lexicographic order so that (a,b) and (b,a) produce the same key.
func pairKey(a, b string) string {
	if a < b {
		return a + "|" + b
	}
	return b + "|" + a
}
