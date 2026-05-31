package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/qryx/internal/store"
)

func recAt(day, score int) store.EvidenceRecord {
	return store.EvidenceRecord{
		CreatedAt: time.Date(2026, 5, day, 12, 0, 0, 0, time.UTC),
		ScorePct:  score, NonCompliant: 5 - score/20, Digest: "sha256:abcdef0123456789",
	}
}

func renderTrend(t *testing.T, recs []store.EvidenceRecord) string {
	t.Helper()
	var buf bytes.Buffer
	Trend(&buf, recs)
	return buf.String()
}

func TestTrendEmpty(t *testing.T) {
	if !strings.Contains(renderTrend(t, nil), "empty") {
		t.Error("empty trail should say empty")
	}
}

func TestTrendDelta(t *testing.T) {
	improve := renderTrend(t, []store.EvidenceRecord{recAt(1, 40), recAt(2, 46)})
	if !strings.Contains(improve, "improved +6") {
		t.Errorf("expected improved +6:\n%s", improve)
	}

	regress := renderTrend(t, []store.EvidenceRecord{recAt(1, 46), recAt(2, 40)})
	if !strings.Contains(regress, "regressed -6") {
		t.Errorf("expected regressed -6:\n%s", regress)
	}

	same := renderTrend(t, []store.EvidenceRecord{recAt(1, 50), recAt(2, 50)})
	if !strings.Contains(same, "unchanged") {
		t.Errorf("expected unchanged:\n%s", same)
	}
}

func TestTrendSingleRecordNoDelta(t *testing.T) {
	out := renderTrend(t, []store.EvidenceRecord{recAt(1, 40)})
	if strings.Contains(out, "improved") || strings.Contains(out, "regressed") || strings.Contains(out, "unchanged") {
		t.Errorf("single record should have no delta line:\n%s", out)
	}
	if !strings.Contains(out, "sha256:abcdef0123") {
		t.Errorf("expected short digest:\n%s", out)
	}
}
