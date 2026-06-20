package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/argus-edr/argus/internal/model"
)

// FileSink appends ECS JSON lines to a file, rotating to "<path>.1" once the
// file passes rotateMaxBytes (0 disables rotation).
type FileSink struct {
	mu             sync.Mutex
	path           string
	rotateMaxBytes int64
	file           *os.File
	size           int64
}

// NewFile opens (creating directories as needed) the log file at path.
func NewFile(path string, rotateMaxBytes int64) (*FileSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &FileSink{path: path, rotateMaxBytes: rotateMaxBytes, file: file, size: info.Size()}, nil
}

func (s *FileSink) WriteEvent(event *model.Event) error {
	return s.write(event.ECS())
}

func (s *FileSink) WriteAlert(alert *model.Alert) error {
	return s.write(alert.ECS())
}

func (s *FileSink) WriteIncident(incident *model.Incident) error {
	return s.write(incident.ECS())
}

func (s *FileSink) write(doc map[string]any) error {
	line, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.rotateIfNeeded(int64(len(line))); err != nil {
		return err
	}
	n, err := s.file.Write(line)
	s.size += int64(n)
	return err
}

func (s *FileSink) rotateIfNeeded(incoming int64) error {
	if s.rotateMaxBytes <= 0 || s.size+incoming <= s.rotateMaxBytes {
		return nil
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	if err := os.Rename(s.path, s.path+".1"); err != nil {
		return err
	}
	file, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	s.file = file
	s.size = 0
	return nil
}

func (s *FileSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Sync()
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Close()
}
