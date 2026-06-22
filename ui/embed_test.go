package ui

import (
	"io/fs"
	"strings"
	"testing"
)

var consoleAssets = []string{"index.html", "app.css", "app.js"}

func TestAssetsEmbedded(t *testing.T) {
	assets := Assets()
	for _, name := range consoleAssets {
		data, err := fs.ReadFile(assets, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("%s is empty", name)
		}
	}
}

// TestNoExternalAssets enforces the zero phone-home principle: the console must
// not load anything from an external origin (no CDN, no remote fonts or
// scripts). Everything is served from the same origin via go:embed.
func TestNoExternalAssets(t *testing.T) {
	assets := Assets()
	forbidden := []string{"http://", "https://", "//cdn", "googleapis", "unpkg", "jsdelivr"}
	for _, name := range consoleAssets {
		data, err := fs.ReadFile(assets, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(data)
		for _, bad := range forbidden {
			if strings.Contains(text, bad) {
				t.Errorf("%s contains external reference %q (violates zero phone-home)", name, bad)
			}
		}
	}
}
