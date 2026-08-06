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

func TestTrendHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := TrendHTML(&buf, []store.EvidenceRecord{recAt(1, 40), recAt(2, 60)}); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	// html/template escapes "+" (e.g. "+20" -> "&#43;20"), so assert on the
	// unescaped parts only.
	for _, want := range []string{"<!DOCTYPE html>", "Compliance Trend", "<svg", "<polyline", "60%", "improved"} {
		if !strings.Contains(html, want) {
			t.Errorf("trend HTML missing %q", want)
		}
	}
}

// TestTrendShowsNotAssessed pins the column that tells a reader what the score
// is a percentage of. Two runs can both read 50% while one graded every asset
// and the other graded half of them, and the trail carries the difference; a
// table that prints only the score hides it.
func TestTrendShowsNotAssessed(t *testing.T) {
	r := recAt(1, 50)
	r.Compliant, r.NonCompliant, r.Issues, r.NotAssessed, r.Total = 2, 1, 0, 1, 4
	out := renderTrend(t, []store.EvidenceRecord{r})

	if !strings.Contains(out, "NOT-ASSESSED") {
		t.Errorf("trend table should carry a not-assessed column:\n%s", out)
	}
	// The count itself, not just the heading: a heading over an absent number
	// is the same omission with a label on it.
	if !strings.Contains(out, "1") {
		t.Errorf("trend table should print the not-assessed count:\n%s", out)
	}
}

// TestTrendNotAssessedIsVisibleAgainstTheTotal checks the same record renders
// both halves of the fact: how many were ungraded, and out of how many.
func TestTrendNotAssessedIsVisibleAgainstTheTotal(t *testing.T) {
	r := recAt(1, 40)
	r.Compliant, r.NonCompliant, r.Issues, r.NotAssessed, r.Total = 4, 2, 0, 4, 10
	out := renderTrend(t, []store.EvidenceRecord{r})

	if !strings.Contains(out, "4 of 10") {
		t.Errorf("expected the ungraded share stated against the inventory it came from:\n%s", out)
	}
}

func TestTrendHTMLShowsNotAssessed(t *testing.T) {
	a, b := recAt(1, 40), recAt(2, 60)
	a.NotAssessed, a.Total = 3, 10
	b.NotAssessed, b.Total = 2, 10

	var buf bytes.Buffer
	if err := TrendHTML(&buf, []store.EvidenceRecord{a, b}); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if !strings.Contains(html, "Not assessed") {
		t.Errorf("trend HTML table should carry a not-assessed column:\n%s", html)
	}
	if !strings.Contains(html, "2 of 10") {
		t.Errorf("trend HTML should state the latest ungraded share against its total:\n%s", html)
	}
}

// TestTrendHTMLFullyAssessedSaysNothingExtra keeps the note honest: when every
// asset was graded there is no caveat to make, and printing "0 of 10 not
// assessed" on every clean run trains the reader to skip the line that matters.
func TestTrendHTMLFullyAssessedSaysNothingExtra(t *testing.T) {
	r := recAt(1, 60)
	r.NotAssessed, r.Total = 0, 10

	var buf bytes.Buffer
	if err := TrendHTML(&buf, []store.EvidenceRecord{r}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "0 of 10") {
		t.Errorf("a fully graded scan should carry no ungraded caveat:\n%s", buf.String())
	}
}

func TestTrendHTMLEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := TrendHTML(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No records") {
		t.Error("empty trend HTML should say no records")
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
