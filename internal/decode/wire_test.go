package decode

import (
	"encoding/binary"
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
