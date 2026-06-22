package ui

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// w3Namespace matches the W3C XML namespace URIs (e.g. the SVG namespace passed
// to document.createElementNS). These are non-resolvable identifiers, never
// fetched over the network, so they are not "external assets" and are stripped
// before the external-reference check below.
var w3Namespace = regexp.MustCompile(`https?://www\.w3\.org/\S*`)

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
		text := w3Namespace.ReplaceAllString(string(data), "")
		for _, bad := range forbidden {
			if strings.Contains(text, bad) {
				t.Errorf("%s contains external reference %q (violates zero phone-home)", name, bad)
			}
		}
	}
}
