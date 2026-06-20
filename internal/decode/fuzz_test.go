package decode

import "testing"

// FuzzDecode asserts the decoder is robust against arbitrary input: it must
// never panic or read out of bounds, must reject buffers shorter than WireSize,
// and must produce a usable event for any buffer it accepts. The decoder reads
// untrusted bytes (replay files, future remote transports), so this is the
// memory-safety boundary.
func FuzzDecode(f *testing.F) {
	f.Add(execWireEvent())
	f.Add(make([]byte, WireSize))
	f.Add(make([]byte, WireSize+512))
	f.Add(make([]byte, WireSize-1))
	f.Add([]byte{})

	decoder := &Decoder{}
	f.Fuzz(func(t *testing.T, raw []byte) {
		event, err := decoder.Decode(raw)
		if len(raw) < WireSize {
			if err == nil {
				t.Fatalf("expected an error for a %d-byte buffer (< WireSize)", len(raw))
			}
			return
		}
		if err != nil {
			return // a long-enough buffer may still be rejected; the point is: no panic
		}
		// Touch the decoded event so any latent out-of-range string handling shows.
		_ = event.ProcessKey()
		_ = event.Type.Action()
	})
}
