package policy

import "testing"

func TestParseValidPolicy(t *testing.T) {
	parsed, err := Parse([]byte("response:\n  mode: dry-run\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Response.Mode != "dry-run" {
		t.Errorf("mode = %q, want dry-run", parsed.Response.Mode)
	}
}

func TestParseRejectsInvalidMode(t *testing.T) {
	if _, err := Parse([]byte("response:\n  mode: destroy\n")); err == nil {
		t.Fatal("expected an error for an invalid mode")
	}
}

func TestParseRejectsUnknownKey(t *testing.T) {
	if _, err := Parse([]byte("bogus: 1\n")); err == nil {
		t.Fatal("expected an error for an unknown key")
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	want := Policy{Response: Response{Mode: "enforce"}}
	data, err := want.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}
