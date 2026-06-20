package decode

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/argus-edr/argus/internal/model"
)

func TestDecodeRejectsShortBuffer(t *testing.T) {
	decoder := &Decoder{}
	if _, err := decoder.Decode(make([]byte, WireSize-1)); err == nil {
		t.Fatal("expected an error decoding a buffer smaller than WireSize")
	}
}

func TestDecodeExecParsesArgv(t *testing.T) {
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

	event, err := (&Decoder{}).Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Process.Executable != "/usr/bin/bash" {
		t.Errorf("executable = %q, want /usr/bin/bash", event.Process.Executable)
	}
	if event.Process.CommandLine != "bash -i" {
		t.Errorf("command_line = %q, want %q", event.Process.CommandLine, "bash -i")
	}
	if len(event.Process.Args) != 2 {
		t.Errorf("args = %v, want 2 elements", event.Process.Args)
	}
}

func TestDecodeConnectParsesEndpoint(t *testing.T) {
	raw := make([]byte, WireSize)
	order := binary.NativeEndian
	order.PutUint32(raw[offType:], uint32(model.EventConnect))
	copy(raw[offSaddr:], []byte{10, 0, 0, 5})
	copy(raw[offDaddr:], []byte{203, 0, 113, 9})
	order.PutUint16(raw[offSport:], 51020)
	order.PutUint16(raw[offDport:], 4444)
	order.PutUint16(raw[offFamily:], 2)

	event, err := (&Decoder{}).Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Network.SrcIP != "10.0.0.5" {
		t.Errorf("src_ip = %q, want 10.0.0.5", event.Network.SrcIP)
	}
	if event.Network.DstIP != "203.0.113.9" {
		t.Errorf("dst_ip = %q, want 203.0.113.9", event.Network.DstIP)
	}
	if event.Network.DstPort != 4444 {
		t.Errorf("dst_port = %d, want 4444", event.Network.DstPort)
	}
}

func TestDecodeConnectParsesIPv6(t *testing.T) {
	raw := make([]byte, WireSize)
	order := binary.NativeEndian
	order.PutUint32(raw[offType:], uint32(model.EventConnect))
	order.PutUint16(raw[offFamily:], afINet6)
	copy(raw[offSaddr:], net.ParseIP("2001:db8::1").To16())
	copy(raw[offDaddr:], net.ParseIP("2001:db8::dead:beef").To16())
	order.PutUint16(raw[offSport:], 40000)
	order.PutUint16(raw[offDport:], 443)

	event, err := (&Decoder{}).Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Network.SrcIP != "2001:db8::1" {
		t.Errorf("src_ip = %q, want 2001:db8::1", event.Network.SrcIP)
	}
	if event.Network.DstIP != "2001:db8::dead:beef" {
		t.Errorf("dst_ip = %q, want 2001:db8::dead:beef", event.Network.DstIP)
	}
	if event.Network.DstPort != 443 {
		t.Errorf("dst_port = %d, want 443", event.Network.DstPort)
	}
}

func TestDecodePtraceReusesFmodeAndRet(t *testing.T) {
	raw := make([]byte, WireSize)
	order := binary.NativeEndian
	order.PutUint32(raw[offType:], uint32(model.EventPtrace))
	order.PutUint16(raw[offFmode:], 16) // PTRACE_ATTACH
	order.PutUint32(raw[offRet:], 4242) // target pid
	order.PutUint32(raw[offPID:], 900)  // tracer pid

	event, err := (&Decoder{}).Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Action != "ptrace" {
		t.Errorf("action = %q, want ptrace", event.Action)
	}
	if event.Syscall.Request != 16 {
		t.Errorf("syscall.request = %d, want 16 (PTRACE_ATTACH)", event.Syscall.Request)
	}
	if event.Syscall.TargetPID != 4242 {
		t.Errorf("syscall.target_pid = %d, want 4242", event.Syscall.TargetPID)
	}
}

func TestDecodeModuleLoadCarriesName(t *testing.T) {
	raw := make([]byte, WireSize)
	binary.NativeEndian.PutUint32(raw[offType:], uint32(model.EventKmod))
	copy(raw[offFilename:], "evil_rootkit\x00")

	event, err := (&Decoder{}).Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Action != "module_load" || event.File.Path != "evil_rootkit" {
		t.Errorf("module load decode = %q path=%q, want module_load/evil_rootkit", event.Action, event.File.Path)
	}
}

func TestDecodeSetuidCarriesNewUID(t *testing.T) {
	raw := make([]byte, WireSize)
	binary.NativeEndian.PutUint32(raw[offType:], uint32(model.EventPrivChange))
	binary.NativeEndian.PutUint32(raw[offRet:], 0) // setuid(0)

	event, err := (&Decoder{}).Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Action != "setuid" || event.Syscall.NewUID != 0 {
		t.Errorf("setuid decode = %q new_uid=%d", event.Action, event.Syscall.NewUID)
	}
}

func TestDecodeOpenIsNotMisreadAsNetwork(t *testing.T) {
	raw := make([]byte, WireSize)
	binary.NativeEndian.PutUint32(raw[offType:], uint32(model.EventOpen))
	copy(raw[offFilename:], "/etc/shadow\x00")

	event, err := (&Decoder{}).Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.File.Path != "/etc/shadow" {
		t.Errorf("file.path = %q, want /etc/shadow", event.File.Path)
	}
	if event.Network.DstIP != "" {
		t.Errorf("open event should have no destination ip, got %q", event.Network.DstIP)
	}
}

func TestDecodeDNSParsesQueriedName(t *testing.T) {
	raw := make([]byte, WireSize)
	order := binary.NativeEndian
	order.PutUint32(raw[offType:], uint32(model.EventDNS))
	order.PutUint16(raw[offFamily:], 2) // AF_INET
	copy(raw[offDaddr:], []byte{203, 0, 113, 53})
	order.PutUint16(raw[offDport:], 53)

	// A DNS query exactly as the sensor forwards it: a 12-byte header (ignored),
	// the QNAME as length-prefixed labels ending in a zero length, then the
	// QTYPE/QCLASS the parser must skip.
	query := make([]byte, 12)
	for _, label := range []string{"telemetry", "corp", "example"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0x00, 0, 1, 0, 1)
	copy(raw[offDomain:], query)

	event, err := (&Decoder{}).Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Action != "dns" {
		t.Errorf("action = %q, want dns", event.Action)
	}
	if event.Network.Domain != "telemetry.corp.example" {
		t.Errorf("domain = %q, want telemetry.corp.example", event.Network.Domain)
	}
	if event.Network.DstIP != "203.0.113.53" {
		t.Errorf("dst_ip = %q, want 203.0.113.53", event.Network.DstIP)
	}
}

func TestDecodeDNSRejectsMalformedQuery(t *testing.T) {
	raw := make([]byte, WireSize)
	binary.NativeEndian.PutUint32(raw[offType:], uint32(model.EventDNS))
	// A label length of 200 — past the 63-byte DNS maximum (a compression pointer
	// or junk) — must yield an empty name, never a bogus or out-of-bounds read.
	raw[offDomain+12] = 200
	event, err := (&Decoder{}).Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Network.Domain != "" {
		t.Errorf("domain = %q, want empty for a malformed query", event.Network.Domain)
	}
}
