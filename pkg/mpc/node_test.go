package mpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortNodeIDs_OrdersLexicographically(t *testing.T) {
	ids := []string{"node-c", "node-a", "node-b"}
	sorted := sortNodeIDs(ids)
	assert.Equal(t, []string{"node-a", "node-b", "node-c"}, sorted)
}

func TestSortNodeIDs_DoesNotMutateInput(t *testing.T) {
	ids := []string{"z", "a", "m"}
	orig := []string{"z", "a", "m"}
	sortNodeIDs(ids)
	assert.Equal(t, orig, ids)
}

func TestSortNodeIDs_Empty(t *testing.T) {
	assert.Empty(t, sortNodeIDs(nil))
	assert.Empty(t, sortNodeIDs([]string{}))
}

func TestSortNodeIDs_SingleElement(t *testing.T) {
	assert.Equal(t, []string{"only"}, sortNodeIDs([]string{"only"}))
}

func TestVersionConstants(t *testing.T) {
	assert.Equal(t, 0, BackwardCompatibleVersion)
	assert.Equal(t, 1, DefaultVersion)
}
