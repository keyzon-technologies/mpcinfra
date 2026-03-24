package security

import (
	"bytes"
	"runtime"
	"testing"
)

func TestZeroBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "non-empty slice",
			data: []byte("sensitive data"),
		},
		{
			name: "empty slice",
			data: []byte{},
		},
		{
			name: "nil slice",
			data: nil,
		},
		{
			name: "single byte",
			data: []byte{0x42},
		},
		{
			name: "binary data",
			data: []byte{0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := make([]byte, len(tt.data))
			copy(original, tt.data)
			
			ZeroBytes(tt.data)
			
			// Verify all bytes are zeroed
			for i, b := range tt.data {
				if b != 0 {
					t.Errorf("byte at index %d not zeroed: got %d, want 0", i, b)
				}
			}
			
			// Verify we didn't panic on edge cases
			if len(tt.data) == 0 {
				// Should handle empty/nil slices gracefully
				return
			}
			
			// Verify the slice was actually modified
			if bytes.Equal(tt.data, original) && len(original) > 0 {
				t.Error("slice was not modified")
			}
		})
	}
}

func TestZeroString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "non-empty string",
			input:    "sensitive password",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single character",
			input:    "x",
			expected: "",
		},
		{
			name:     "unicode string",
			input:    "🔐password🔑",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.input
			
			ZeroString(&s)
			
			// Verify string is now empty
			if s != tt.expected {
				t.Errorf("string not cleared: got %q, want %q", s, tt.expected)
			}
			
			// Note: We can't reliably test if the underlying memory was zeroed
			// because Go strings are immutable and memory clearing depends on GC timing
		})
	}
}

func TestZeroStringNilPointer(t *testing.T) {
	// Test that ZeroString handles nil pointer gracefully
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ZeroString panicked with nil pointer: %v", r)
		}
	}()
	
	ZeroString(nil)
}

func TestSecureBytes(t *testing.T) {
	t.Run("basic functionality", func(t *testing.T) {
		original := []byte("secret data")
		sb := NewSecureBytes(original)
		
		// Verify data is accessible
		data := sb.Bytes()
		if !bytes.Equal(data, original) {
			t.Errorf("SecureBytes data mismatch: got %v, want %v", data, original)
		}
		
		// Verify copy works
		copied := sb.Copy()
		if !bytes.Equal(copied, original) {
			t.Errorf("SecureBytes copy mismatch: got %v, want %v", copied, original)
		}
		
		// Verify modifying copy doesn't affect original
		copied[0] = 'X'
		if bytes.Equal(sb.Bytes(), copied) {
			t.Error("SecureBytes copy shares memory with original")
		}
	})
	
	t.Run("manual clear", func(t *testing.T) {
		sb := NewSecureBytes([]byte("secret"))
		sb.Clear()
		
		// After Clear(), data should be nil
		if sb.data != nil {
			t.Error("SecureBytes data not nil after Clear()")
		}
		
		// Calling Clear() again should not panic
		sb.Clear()
	})
	
	t.Run("finalizer behavior", func(t *testing.T) {
		// This test verifies that the finalizer doesn't panic
		// We can't easily test that it actually zeros memory due to GC timing
		func() {
			sb := NewSecureBytes([]byte("secret"))
			_ = sb // Use the variable to prevent optimization
		}()
		
		// Force garbage collection to potentially trigger finalizer
		runtime.GC()
		runtime.GC()
		
		// If we reach here without panic, the finalizer worked correctly
	})
	
	t.Run("empty data", func(t *testing.T) {
		sb := NewSecureBytes([]byte{})
		
		if len(sb.Bytes()) != 0 {
			t.Error("SecureBytes should handle empty data")
		}
		
		sb.Clear()
		// Should not panic
	})
	
	t.Run("nil data", func(t *testing.T) {
		sb := NewSecureBytes(nil)
		
		if sb.Bytes() == nil {
			t.Error("SecureBytes should create empty slice for nil input")
		}
		
		if len(sb.Bytes()) != 0 {
			t.Error("SecureBytes should create empty slice for nil input")
		}
	})
}

func TestSecureBytesIsolation(t *testing.T) {
	// Verify that SecureBytes creates its own copy of data
	original := []byte("secret data")
	sb := NewSecureBytes(original)
	
	// Modify the original
	original[0] = 'X'
	
	// SecureBytes should be unaffected
	if sb.Bytes()[0] == 'X' {
		t.Error("SecureBytes shares memory with input data")
	}
}

// Benchmark tests to ensure performance is reasonable
func BenchmarkZeroBytes(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset data for each iteration
		for j := range data {
			data[j] = byte(j % 256)
		}
		ZeroBytes(data)
	}
}

func BenchmarkZeroString(b *testing.B) {
	original := "this is a test string that represents a password or other sensitive data"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := original
		ZeroString(&s)
	}
}

func BenchmarkSecureBytes(b *testing.B) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb := NewSecureBytes(data)
		_ = sb.Copy()
		sb.Clear()
	}
}