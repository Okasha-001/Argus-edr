package correlate

import (
	"testing"
	"time"

	"github.com/argus-edr/argus/server/store"
)

func alert(host, technique, dst string, at time.Time) store.AlertRecord {
	return store.AlertRecord{Hostname: host, TechniqueID: technique, DestinationIP: dst, Time: at}
}

func TestLateralMovementFiresOnceAtThreshold(t *testing.T) {
	cross := NewCrossHost(time.Hour, 2)
	now := time.Unix(1000, 0)

	if signals := cross.Observe(alert("web-01", "T1059", "", now)); len(signals) != 0 {
		t.Fatalf("one host should not fire a signal, got %+v", signals)
	}
	signals := cross.Observe(alert("db-01", "T1059", "", now))
	if len(signals) != 1 {
		t.Fatalf("a second host should fire one signal, got %d", len(signals))
	}
	if signals[0].Kind != KindLateralMovement || signals[0].Key != "T1059" {
		t.Errorf("signal = %+v, want lateral-movement on T1059", signals[0])
	}
	if len(signals[0].Hosts) != 2 {
		t.Errorf("signal should name both hosts, got %v", signals[0].Hosts)
	}
	// A third host on the same technique must not re-fire the same signal.
	if signals := cross.Observe(alert("app-01", "T1059", "", now)); len(signals) != 0 {
		t.Errorf("signal should fire once per window, got %+v", signals)
	}
}

func TestC2FanInByDestination(t *testing.T) {
	cross := NewCrossHost(time.Hour, 2)
	now := time.Unix(1000, 0)
	cross.Observe(alert("web-01", "", "203.0.113.9", now))
	signals := cross.Observe(alert("db-01", "", "203.0.113.9", now))
	if len(signals) != 1 || signals[0].Kind != KindC2FanIn || signals[0].Key != "203.0.113.9" {
		t.Fatalf("signals = %+v, want c2-fanin on 203.0.113.9", signals)
	}
}

func TestStaleHostsExpireFromWindow(t *testing.T) {
	cross := NewCrossHost(time.Minute, 2)
	base := time.Unix(1000, 0)
	cross.Observe(alert("web-01", "T1059", "", base))
	// The second host arrives after the window; the first has aged out, so the
	// distinct-host count never reaches the threshold.
	if signals := cross.Observe(alert("db-01", "T1059", "", base.Add(2*time.Minute))); len(signals) != 0 {
		t.Errorf("expired host should not contribute to the threshold, got %+v", signals)
	}
}

func TestEmptyKeysIgnored(t *testing.T) {
	cross := NewCrossHost(time.Hour, 1)
	if signals := cross.Observe(alert("web-01", "", "", time.Unix(1000, 0))); len(signals) != 0 {
		t.Errorf("an alert with no technique or destination should not signal, got %+v", signals)
	}
}
