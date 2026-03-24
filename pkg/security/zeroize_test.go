package security

import (
	"testing"
)

func TestZeroBytes_OverwritesAll(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("expected byte %d to be zero", i)
		}
	}
}

func TestZeroString_ClearsString(t *testing.T) {
	s := "secret"
	ZeroString(&s)
	if s != "" {
		t.Fatalf("expected string to be empty after ZeroString, got %q", s)
	}
}

func TestZeroString_NilSafe(t *testing.T) {
	ZeroString(nil) // must not panic
}

func TestZeroString_EmptySafe(t *testing.T) {
	s := ""
	ZeroString(&s) // must not panic
}
