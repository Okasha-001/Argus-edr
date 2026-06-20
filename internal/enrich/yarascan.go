package enrich

import (
	"io"
	"os"

	"github.com/argus-edr/argus/internal/yara"
)

// YaraScanner scans an executable's bytes against a compiled YARA rule set and
// returns the names of the rules that matched. It reads at most maxBytes per file
// so a huge binary can't stall the pipeline.
type YaraScanner struct {
	engine   *yara.Engine
	maxBytes int64
}

// NewYaraScanner returns a scanner over engine, reading at most maxBytes per file
// (<= 0 means no limit).
func NewYaraScanner(engine *yara.Engine, maxBytes int64) *YaraScanner {
	return &YaraScanner{engine: engine, maxBytes: maxBytes}
}

// Scan returns the matching rule names for the regular file at path, or nil if it
// cannot be read or nothing matched.
func (s *YaraScanner) Scan(path string) []string {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var reader io.Reader = file
	if s.maxBytes > 0 {
		reader = io.LimitReader(file, s.maxBytes)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil
	}
	return s.engine.Scan(data)
}
