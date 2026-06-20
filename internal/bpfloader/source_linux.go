//go:build linux

// Package bpfloader loads the compiled eBPF objects, attaches the programs, and
// streams decoded events from the ring buffers as a pipeline.Source.
package bpfloader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/argus-edr/argus/internal/decode"
	"github.com/argus-edr/argus/internal/model"
)

// Options configures the eBPF source.
type Options struct {
	ObjectPath    string // compiled sensor object (edr.bpf.o)
	LSMObjectPath string // optional enforcement object (edr_lsm.bpf.o)
	Hostname      string
	EnforceMode   uint32 // 0 off, 1 dry-run, 2 enforce
	Logger        *slog.Logger
}

type attachSpec struct {
	program string // C function name == program key in the collection
	kind    string // tp | kprobe | kretprobe
	group   string // tracepoint group
	target  string // tracepoint name or kprobe symbol
}

var sensorAttachments = []attachSpec{
	{"handle_execve", "tp", "syscalls", "sys_enter_execve"},
	{"handle_exec", "tp", "sched", "sched_process_exec"},
	{"handle_fork", "tp", "sched", "sched_process_fork"},
	{"handle_exit", "tp", "sched", "sched_process_exit"},
	{"handle_openat", "tp", "syscalls", "sys_enter_openat"},
	{"handle_unlinkat", "tp", "syscalls", "sys_enter_unlinkat"},
	{"handle_renameat2", "tp", "syscalls", "sys_enter_renameat2"},
	{"handle_fchmodat", "tp", "syscalls", "sys_enter_fchmodat"},
	{"handle_tcp_connect", "kprobe", "", "tcp_connect"},
	{"handle_inet_accept", "kretprobe", "", "inet_csk_accept"},
	{"handle_ptrace", "tp", "syscalls", "sys_enter_ptrace"},
	{"handle_init_module", "kprobe", "", "do_init_module"},
	{"handle_bpf", "tp", "syscalls", "sys_enter_bpf"},
	{"handle_memfd", "tp", "syscalls", "sys_enter_memfd_create"},
	{"handle_mmap_file", "kprobe", "", "security_mmap_file"},
	{"handle_file_open", "kprobe", "", "security_file_open"},
	{"handle_setuid", "tp", "syscalls", "sys_enter_setuid"},
	{"handle_sendto", "tp", "syscalls", "sys_enter_sendto"},
}

// EBPFSource loads the objects and feeds decoded events into the pipeline.
type EBPFSource struct {
	opts    Options
	decoder *decode.Decoder
	logger  *slog.Logger

	colls   []*ebpf.Collection
	links   []link.Link
	readers []*ringbuf.Reader

	closeOnce sync.Once
}

// NewEBPFSource builds a source from the given options.
func NewEBPFSource(opts Options) *EBPFSource {
	return &EBPFSource{
		opts:    opts,
		decoder: &decode.Decoder{Hostname: opts.Hostname, BootUnixNano: bootUnixNano()},
		logger:  opts.Logger,
	}
}

// Run loads the programs and streams events until ctx is cancelled.
func (s *EBPFSource) Run(ctx context.Context, out chan<- *model.Event) error {
	if err := s.loadSensors(); err != nil {
		return err
	}
	if s.opts.LSMObjectPath != "" {
		s.loadEnforcement()
	}
	defer s.Close()

	go func() {
		<-ctx.Done()
		s.closeReaders()
	}()

	var wg sync.WaitGroup
	for _, reader := range s.readers {
		wg.Add(1)
		go func(rd *ringbuf.Reader) {
			defer wg.Done()
			s.consume(ctx, rd, out)
		}(reader)
	}
	wg.Wait()
	return nil
}

func (s *EBPFSource) loadSensors() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	coll, err := loadCollection(s.opts.ObjectPath)
	if err != nil {
		return err
	}
	s.colls = append(s.colls, coll)

	for _, spec := range sensorAttachments {
		program, ok := coll.Programs[spec.program]
		if !ok {
			s.logger.Warn("sensor program not found in object", "program", spec.program)
			continue
		}
		lnk, err := attachProgram(spec, program)
		if err != nil {
			s.logger.Warn("attach failed (kernel may lack this hook)", "program", spec.program, "err", err)
			continue
		}
		s.links = append(s.links, lnk)
	}

	reader, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("open events ring buffer: %w", err)
	}
	s.readers = append(s.readers, reader)
	return nil
}

// loadEnforcement is best-effort: enforcement needs CONFIG_BPF_LSM and "bpf" in
// the kernel's lsm= list, so a failure here is logged, not fatal.
func (s *EBPFSource) loadEnforcement() {
	coll, err := loadCollection(s.opts.LSMObjectPath)
	if err != nil {
		s.logger.Warn("enforcement object not loaded", "err", err)
		return
	}
	s.colls = append(s.colls, coll)

	if err := coll.Maps["enforce_config"].Put(uint32(0), s.opts.EnforceMode); err != nil {
		s.logger.Warn("set enforcement mode failed", "err", err)
	}
	program, ok := coll.Programs["bprm_check"]
	if !ok {
		s.logger.Warn("enforcement program bprm_check missing")
		return
	}
	lnk, err := link.AttachLSM(link.LSMOptions{Program: program})
	if err != nil {
		s.logger.Warn("attach LSM failed (is BPF LSM enabled in lsm= boot param?)", "err", err)
		return
	}
	s.links = append(s.links, lnk)

	reader, err := ringbuf.NewReader(coll.Maps["enforce_events"])
	if err != nil {
		s.logger.Warn("open enforcement ring buffer failed", "err", err)
		return
	}
	s.readers = append(s.readers, reader)
	s.logger.Info("enforcement loaded", "mode", s.opts.EnforceMode)
}

func (s *EBPFSource) consume(ctx context.Context, reader *ringbuf.Reader, out chan<- *model.Event) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			s.logger.Error("ring buffer read", "err", err)
			continue
		}
		event, err := s.decoder.Decode(record.RawSample)
		if err != nil {
			s.logger.Warn("decode event", "err", err)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case out <- event:
		}
	}
}

// Close detaches everything and frees the objects. Safe to call more than once.
func (s *EBPFSource) Close() error {
	s.closeOnce.Do(func() {
		s.closeReaders()
		for _, lnk := range s.links {
			_ = lnk.Close()
		}
		for _, coll := range s.colls {
			coll.Close()
		}
	})
	return nil
}

func (s *EBPFSource) closeReaders() {
	for _, reader := range s.readers {
		_ = reader.Close()
	}
}

func loadCollection(path string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("load spec %s: %w", path, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			return nil, fmt.Errorf("verifier rejected %s: %+v", path, verifierErr)
		}
		return nil, fmt.Errorf("load collection %s: %w", path, err)
	}
	return coll, nil
}

func attachProgram(spec attachSpec, program *ebpf.Program) (link.Link, error) {
	switch spec.kind {
	case "tp":
		return link.Tracepoint(spec.group, spec.target, program, nil)
	case "kprobe":
		return link.Kprobe(spec.target, program, nil)
	case "kretprobe":
		return link.Kretprobe(spec.target, program, nil)
	default:
		return nil, fmt.Errorf("unknown attach kind %q", spec.kind)
	}
}

// bootUnixNano anchors the kernel's CLOCK_BOOTTIME timestamps to wall-clock time
// so decoded events carry real @timestamps.
func bootUnixNano() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Now().UnixNano()
	}
	return time.Now().UnixNano() - ts.Nano()
}
