package intel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/argus-edr/argus/internal/model"
)

const badHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func writeFeed(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadInfersIndicatorTypes(t *testing.T) {
	feed := writeFeed(t, "iocs.txt", `
# malicious indicators
203.0.113.66            # known C2
198.51.100.0/24         # bad subnet
evil.example
`+badHash+`
`)
	matcher, err := Load(feed)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if matcher.Size() != 4 {
		t.Fatalf("Size = %d, want 4 (ip, cidr, domain, hash)", matcher.Size())
	}
}

func TestMatchByEachIndicatorType(t *testing.T) {
	feed := writeFeed(t, "iocs.txt", "203.0.113.66\n198.51.100.0/24\nevil.example\n"+badHash+"\n")
	matcher, err := Load(feed)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	cases := []struct {
		name      string
		event     *model.Event
		wantType  string
		wantField string
	}{
		{"exact ip", &model.Event{Network: model.Network{DstIP: "203.0.113.66"}}, TypeIP, "destination.ip"},
		{"cidr ip", &model.Event{Network: model.Network{DstIP: "198.51.100.9"}}, TypeIP, "destination.ip"},
		{"source ip", &model.Event{Network: model.Network{SrcIP: "203.0.113.66"}}, TypeIP, "source.ip"},
		{"domain", &model.Event{Network: model.Network{Domain: "EVIL.example"}}, TypeDomain, "network.domain"},
		{"hash", &model.Event{Process: model.Process{SHA256: badHash}}, TypeHash, "process.sha256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := matcher.Match(tc.event)
			if len(hits) != 1 {
				t.Fatalf("got %d hits, want 1: %+v", len(hits), hits)
			}
			if hits[0].Type != tc.wantType || hits[0].Field != tc.wantField {
				t.Errorf("hit = %+v, want type %s on %s", hits[0], tc.wantType, tc.wantField)
			}
			if hits[0].Source != "iocs.txt" {
				t.Errorf("source = %q, want iocs.txt", hits[0].Source)
			}
		})
	}
}

func TestCleanEventHasNoHits(t *testing.T) {
	feed := writeFeed(t, "iocs.txt", "203.0.113.66\n")
	matcher, _ := Load(feed)
	event := &model.Event{Network: model.Network{DstIP: "203.0.113.1"}, Process: model.Process{SHA256: badHash}}
	if hits := matcher.Match(event); len(hits) != 0 {
		t.Errorf("expected no hits for a clean event, got %+v", hits)
	}
}

func TestMatchIsCaseInsensitiveForDomainAndHash(t *testing.T) {
	feed := writeFeed(t, "iocs.txt", "Evil.Example\n"+badHash+"\n")
	matcher, _ := Load(feed)
	event := &model.Event{
		Network: model.Network{Domain: "evil.example"},
		Process: model.Process{SHA256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}
	if hits := matcher.Match(event); len(hits) != 2 {
		t.Errorf("case-insensitive match failed: got %+v", hits)
	}
}

func TestLoadMissingFeedErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.txt")); err == nil {
		t.Fatal("expected an error for a missing feed file")
	}
}
