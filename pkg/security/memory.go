package security

import (
	"runtime"
)

// ZeroBytes securely zeros out a byte slice to prevent sensitive data from
// remaining in memory. This uses explicit memory zeroing and garbage collection
// to help ensure the data is actually cleared.
func ZeroBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	
	// Zero out the slice
	for i := range data {
		data[i] = 0
	}
	
	// Force garbage collection to help ensure the zeroed memory is reclaimed
	runtime.GC()
}

// ZeroString securely clears a string reference and encourages garbage collection.
// Note: Go strings are immutable, so we can only clear the reference and rely on GC.
// This provides best-effort security by clearing the reference and forcing GC.
func ZeroString(s *string) {
	if s == nil {
		return
	}
	
	// Clear the string reference - this is the safe approach
	// The actual string data will be garbage collected
	*s = ""
	
	// Force garbage collection to help clear the original string data from memory
	// This is best-effort as GC timing is not guaranteed
	runtime.GC()
	runtime.GC() // Run twice to increase chances of collection
}

// SecureBytes is a wrapper for sensitive byte data that automatically
// zeros itself when no longer needed
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a new SecureBytes instance
func NewSecureBytes(data []byte) *SecureBytes {
	// Make a copy to ensure we own the memory
	copied := make([]byte, len(data))
	copy(copied, data)
	
	sb := &SecureBytes{data: copied}
	
	// Set finalizer to zero memory when GC'd
	runtime.SetFinalizer(sb, (*SecureBytes).zero)
	
	return sb
}

// Bytes returns the underlying byte slice (use with caution)
func (sb *SecureBytes) Bytes() []byte {
	return sb.data
}

// Copy returns a copy of the data
func (sb *SecureBytes) Copy() []byte {
	result := make([]byte, len(sb.data))
	copy(result, sb.data)
	return result
}

// Clear explicitly zeros the data and removes the finalizer
func (sb *SecureBytes) Clear() {
	sb.zero()
	runtime.SetFinalizer(sb, nil)
}

// zero securely clears the data
func (sb *SecureBytes) zero() {
	if sb.data != nil {
		ZeroBytes(sb.data)
		sb.data = nil
	}
}