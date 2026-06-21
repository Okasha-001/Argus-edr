//go:build linux

// Package bpfloader loads the compiled eBPF objects, attaches the programs, and
// streams decoded events from the ring buffers as a pipeline.Source.
package bpfloader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
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
	EnforceMode   uint32   // 0 off, 1 dry-run, 2 enforce
	CredReaders   []string // process comms exempt from the file_open credential guard
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

// taskCommLen mirrors TASK_COMM_LEN in bpf/common.h: the fixed width of a comm
// as the kernel stores it, and the key width of the cred_readers map.
const taskCommLen = 16

// lsmPrograms names the enforcement programs in the LSM object, attached together
// when an object is present. Each is gated by the shared enforce_config mode, so
// listing one here never turns it on — that still takes response.mode.
var lsmPrograms = []string{"bprm_check", "task_kill", "ptrace_guard", "file_open_guard"}

// EBPFSource loads the objects and feeds decoded events into the pipeline.
type EBPFSource struct {
	opts    Options
	decoder *decode.Decoder
	logger  *slog.Logger

	colls    []*ebpf.Collection
	links    []link.Link
	readers  []*ringbuf.Reader
	dropMap  *ebpf.Map                // per-CPU ring-drop counter, read for the loss metric
	programs map[string]*ebpf.Program // attached sensor programs, for per-program cost
	stats    io.Closer                // kernel run-time stats collection, while open

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

	s.programs = make(map[string]*ebpf.Program)
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
		s.programs[spec.program] = program
	}
	s.enableRuntimeStats()

	reader, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("open events ring buffer: %w", err)
	}
	s.readers = append(s.readers, reader)
	s.dropMap = coll.Maps["dropped"] // may be absent in an older object; RingDrops handles nil
	return nil
}

// RingDrops returns the total events the kernel dropped because the ring buffer
// was full, summed across CPUs. It is the userspace read of the per-CPU `dropped`
// counter, exposed as the event-loss metric. Best-effort: a missing map or a read
// error reports zero rather than failing a scrape.
func (s *EBPFSource) RingDrops() uint64 {
	if s.dropMap == nil {
		return 0
	}
	var perCPU []uint64
	if err := s.dropMap.Lookup(uint32(0), &perCPU); err != nil {
		return 0
	}
	var total uint64
	for _, count := range perCPU {
		total += count
	}
	return total
}

// enableRuntimeStats turns on the kernel's per-program run-time accounting so
// ProgramStats can report each sensor's cost. It needs CAP_SYS_ADMIN and is
// best-effort: without it the cost metric simply reads zero.
func (s *EBPFSource) enableRuntimeStats() {
	closer, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		s.logger.Warn("per-program runtime stats disabled (needs CAP_SYS_ADMIN)", "err", err)
		return
	}
	s.stats = closer
}

// ProgramStats reports the cumulative runtime and run count of each attached
// sensor program. Values are zero unless runtime stats were enabled at load.
func (s *EBPFSource) ProgramStats() []ProgramStat {
	stats := make([]ProgramStat, 0, len(s.programs))
	for name, program := range s.programs {
		info, err := program.Stats()
		if err != nil {
			continue
		}
		stats = append(stats, ProgramStat{Name: name, Runtime: info.Runtime, RunCount: info.RunCount})
	}
	return stats
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
	s.armSelfProtection(coll)
	s.loadCredReaderAllowlist(coll)

	for _, name := range lsmPrograms {
		program, ok := coll.Programs[name]
		if !ok {
			continue // an older object may not carry every enforcement hook
		}
		lnk, err := link.AttachLSM(link.LSMOptions{Program: program})
		if err != nil {
			s.logger.Warn("attach LSM failed (is BPF LSM enabled in lsm= boot param?)",
				"program", name, "err", err)
			continue
		}
		s.links = append(s.links, lnk)
	}

	reader, err := ringbuf.NewReader(coll.Maps["enforce_events"])
	if err != nil {
		s.logger.Warn("open enforcement ring buffer failed", "err", err)
		return
	}
	s.readers = append(s.readers, reader)
	s.logger.Info("enforcement loaded", "mode", s.opts.EnforceMode)
}

// armSelfProtection tells the self-protection hooks which pid is the agent's, so
// task_kill (and the ptrace hook) can recognise an attempt against ARGUS itself.
// A missing map means an older enforcement object without the feature — the hooks
// simply stay inert, never failing the load.
func (s *EBPFSource) armSelfProtection(coll *ebpf.Collection) {
	guard, ok := coll.Maps["protected_pid"]
	if !ok {
		return
	}
	if err := guard.Put(uint32(0), uint32(os.Getpid())); err != nil {
		s.logger.Warn("arm self-protection failed", "err", err)
	}
}

// loadCredReaderAllowlist populates the kernel map of comms exempt from the
// file_open credential guard. The key is the comm exactly as the kernel reports
// it: a fixed TASK_COMM_LEN buffer, the name followed by zero padding.
func (s *EBPFSource) loadCredReaderAllowlist(coll *ebpf.Collection) {
	readers, ok := coll.Maps["cred_readers"]
	if !ok {
		return
	}
	for _, comm := range s.opts.CredReaders {
		var key [taskCommLen]byte
		copy(key[:], comm)
		if err := readers.Put(key, uint8(1)); err != nil {
			s.logger.Warn("add cred-reader allowlist entry failed", "comm", comm, "err", err)
		}
	}
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
		if s.stats != nil {
			_ = s.stats.Close()
		}
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
