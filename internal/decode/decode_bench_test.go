package decode

import (
	"encoding/binary"
	"testing"

	"github.com/argus-edr/argus/internal/model"
)

// execWireEvent builds a realistic exec event in the wire format, matching the
// layout the kernel sensor emits. Shared by the decode benchmark and fuzzer.
func execWireEvent() []byte {
	raw := make([]byte, WireSize)
	order := binary.NativeEndian
	order.PutUint32(raw[offType:], uint32(model.EventExec))
	order.PutUint32(raw[offPID:], 4123)
	order.PutUint32(raw[offPPID:], 4001)
	copy(raw[offComm:], "bash\x00")
	copy(raw[offFilename:], "/usr/bin/bash\x00")
	argv := "bash\x00-i\x00"
	copy(raw[offArgs:], argv)
	order.PutUint32(raw[offArgsLen:], uint32(len(argv)))
	return raw
}

// BenchmarkDecodeExec measures the per-event cost of decoding the busiest event
// type (exec, which also parses argv) from the ring buffer into a model.Event.
func BenchmarkDecodeExec(b *testing.B) {
	raw := execWireEvent()
	decoder := &Decoder{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := decoder.Decode(raw); err != nil {
			b.Fatal(err)
		}
	}
}
