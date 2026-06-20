// Package decode turns the raw bytes read from the ring buffer into model
// Events. The wire layout is the mirror of struct event in bpf/common.h; the
// offsets below are asserted against that size in the tests.
package decode

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

const (
	commLen     = 16
	filenameLen = 256
	argsLen     = 512
	domainLen   = 256
	addrLen     = 16 // saddr/daddr each hold an IPv6 address; IPv4 uses 4 bytes

	// WireSize is sizeof(struct event) — kept in lockstep with bpf/common.h.
	WireSize = 1128

	afINet6 = 10 // AF_INET6; anything else is treated as IPv4
)

// Byte offsets of each field within the wire struct (mirror of struct event).
const (
	offTimestamp = 0
	offCgroupID  = 8
	offType      = 16
	offPID       = 20
	offTID       = 24
	offPPID      = 28
	offUID       = 32
	offRet       = 40
	offArgsLen   = 44
	offSport     = 48
	offDport     = 50
	offFamily    = 52
	offFmode     = 54
	offSaddr     = 56
	offDaddr     = offSaddr + addrLen
	offComm      = offDaddr + addrLen
	offFilename  = offComm + commLen
	offArgs      = offFilename + filenameLen
	offDomain    = offArgs + argsLen
)

// Decoder converts ring-buffer records to events. BootUnixNano anchors the
// kernel's monotonic timestamps to wall-clock time; Hostname stamps each event.
type Decoder struct {
	BootUnixNano int64
	Hostname     string
}

// Decode parses one wire record. The kernel and agent share an architecture, so
// fixed-width fields use the host byte order; the IPv4 addresses are read as raw
// network-order bytes, which keeps them correct regardless of endianness.
func (d *Decoder) Decode(raw []byte) (*model.Event, error) {
	if len(raw) < WireSize {
		return nil, fmt.Errorf("short event: got %d bytes, want %d", len(raw), WireSize)
	}
	order := binary.NativeEndian

	monotonic := order.Uint64(raw[offTimestamp:])
	event := &model.Event{
		SchemaVersion: model.SchemaVersion,
		MonotonicNs:   monotonic,
		Timestamp:     time.Unix(0, d.BootUnixNano+int64(monotonic)).UTC(),
		Host:          d.Hostname,
		Type:          model.EventType(order.Uint32(raw[offType:])),
		CgroupID:      order.Uint64(raw[offCgroupID:]),
		Ret:           int32(order.Uint32(raw[offRet:])),
	}
	event.Action = event.Type.Action()
	event.Process = model.Process{
		PID:  order.Uint32(raw[offPID:]),
		TID:  order.Uint32(raw[offTID:]),
		PPID: order.Uint32(raw[offPPID:]),
		Name: cstr(raw[offComm : offComm+commLen]),
	}
	event.User = model.User{ID: order.Uint32(raw[offUID:])}

	d.applyTypeSpecific(event, raw)
	return event, nil
}

func (d *Decoder) applyTypeSpecific(event *model.Event, raw []byte) {
	order := binary.NativeEndian
	filename := cstr(raw[offFilename : offFilename+filenameLen])
	mode := order.Uint16(raw[offFmode:])

	switch event.Type {
	case model.EventExec, model.EventExecBlocked:
		event.Process.Executable = filename
		event.Process.StartTimeNs = event.MonotonicNs
		event.Process.Args = parseArgs(raw[offArgs:offArgs+argsLen], order.Uint32(raw[offArgsLen:]))
		event.Process.CommandLine = strings.Join(event.Process.Args, " ")
	case model.EventExit:
		event.Process.ExitCode = event.Ret
	case model.EventOpen:
		event.File = model.File{Path: filename, Flags: mode}
	case model.EventUnlink:
		event.File = model.File{Path: filename}
	case model.EventRename:
		event.File = model.File{Path: filename, Target: cstr(raw[offArgs : offArgs+argsLen])}
	case model.EventChmod:
		event.File = model.File{Path: filename, Mode: mode}
	case model.EventConnect, model.EventAccept:
		family := order.Uint16(raw[offFamily:])
		event.Network = model.Network{
			Family:  family,
			SrcIP:   ipAddr(family, raw[offSaddr:offSaddr+addrLen]),
			SrcPort: order.Uint16(raw[offSport:]),
			DstIP:   ipAddr(family, raw[offDaddr:offDaddr+addrLen]),
			DstPort: order.Uint16(raw[offDport:]),
		}
	case model.EventPtrace:
		// fmode = request, ret = target pid (see bpf/common.h).
		event.Syscall = model.Syscall{Request: int64(mode), TargetPID: uint32(event.Ret)}
	case model.EventKmod, model.EventMemfd:
		event.File = model.File{Path: filename} // module name / memfd name
	case model.EventBPF, model.EventMmapExec:
		event.Syscall = model.Syscall{Request: int64(mode)} // bpf cmd / mmap prot
	case model.EventPrivChange:
		event.Syscall = model.Syscall{NewUID: uint32(event.Ret)}
	case model.EventDNS:
		event.Network = model.Network{
			Family:  order.Uint16(raw[offFamily:]),
			DstIP:   ipv4(raw[offDaddr : offDaddr+4]),
			DstPort: order.Uint16(raw[offDport:]),
			Domain:  parseDNSName(raw[offDomain : offDomain+domainLen]),
		}
	}
}

// parseDNSName extracts the queried name from the raw bytes of a DNS query
// message the sensor captured. The kernel forwards the message verbatim (sensors
// are dumb); the agent does the parsing. Layout: a 12-byte header, then QNAME as
// length-prefixed labels terminated by a zero length. Returns "" if the bytes are
// too short or malformed, so a junk packet never produces a bogus domain.
func parseDNSName(query []byte) string {
	const dnsHeaderLen = 12
	if len(query) <= dnsHeaderLen {
		return ""
	}
	labels := query[dnsHeaderLen:]
	var name strings.Builder
	for offset := 0; offset < len(labels); {
		length := int(labels[offset])
		if length == 0 {
			break // end of QNAME
		}
		if length > 63 || offset+1+length > len(labels) {
			return "" // not a valid label sequence
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(labels[offset+1 : offset+1+length])
		offset += 1 + length
	}
	return name.String()
}

func cstr(b []byte) string {
	if i := indexZero(b); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// parseArgs splits the NUL-separated argv blob the execve sensor packed.
func parseArgs(blob []byte, used uint32) []string {
	if int(used) < len(blob) {
		blob = blob[:used]
	}
	parts := strings.Split(string(blob), "\x00")
	args := parts[:0]
	for _, p := range parts {
		if p != "" {
			args = append(args, p)
		}
	}
	return args
}

// ipAddr formats a wire address field, which is addrLen bytes wide. An AF_INET6
// event fills all of them; anything else (AF_INET) uses the first four.
func ipAddr(family uint16, b []byte) string {
	if family == afINet6 {
		return ipv6(b)
	}
	return ipv4(b[:4])
}

func ipv4(b []byte) string {
	if allZero(b) {
		return ""
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func ipv6(b []byte) string {
	if allZero(b) {
		return ""
	}
	return net.IP(b).String()
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
