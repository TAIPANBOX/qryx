package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJSONLTrailAppendAndHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trail.jsonl")
	trail := JSONLTrail{Path: path}

	r1 := EvidenceRecord{CreatedAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), Root: "x", ScorePct: 40, NonCompliant: 3, Digest: "sha256:aaa"}
	r2 := EvidenceRecord{CreatedAt: time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC), Root: "x", ScorePct: 55, NonCompliant: 2, Digest: "sha256:bbb"}
	if err := trail.Append(r1); err != nil {
		t.Fatal(err)
	}
	if err := trail.Append(r2); err != nil {
		t.Fatal(err)
	}

	hist, err := trail.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("history len=%d want 2", len(hist))
	}
	if hist[0].ScorePct != 40 || hist[1].ScorePct != 55 {
		t.Errorf("append order wrong: %+v", hist)
	}
	if !hist[0].CreatedAt.Equal(r1.CreatedAt) || hist[1].Digest != "sha256:bbb" {
		t.Errorf("round-trip mismatch: %+v", hist)
	}
}

// TestJSONLTrailCarriesNotAssessed pins the fourth count through the file
// backend. The record already carried a Total that included ungraded assets, so
// without this field the trail states a whole whose parts do not add up and
// leaves the reader to work the remainder out by subtraction.
func TestJSONLTrailCarriesNotAssessed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trail.jsonl")
	trail := JSONLTrail{Path: path}

	rec := EvidenceRecord{
		CreatedAt: time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC), Root: "x", ScorePct: 25,
		Compliant: 1, NonCompliant: 1, Issues: 1, NotAssessed: 1, Total: 4, Digest: "sha256:ccc",
	}
	if err := trail.Append(rec); err != nil {
		t.Fatal(err)
	}
	hist, err := trail.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("history len=%d want 1", len(hist))
	}
	if hist[0].NotAssessed != 1 {
		t.Errorf("NotAssessed = %d, want 1: %+v", hist[0].NotAssessed, hist[0])
	}
	got := hist[0]
	if sum := got.Compliant + got.NonCompliant + got.Issues + got.NotAssessed; sum != got.Total {
		t.Errorf("counts sum to %d but Total = %d: %+v", sum, got.Total, got)
	}
}

// TestJSONLTrailRecordWithoutNotAssessedDecodesAsZero states the compatibility
// promise rather than leaving somebody to discover it: a trail written before
// the field existed still reads, and its records report zero ungraded assets,
// which is what they meant when every asset was graded one of three ways.
func TestJSONLTrailRecordWithoutNotAssessedDecodesAsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.jsonl")
	old := `{"createdAt":"2026-05-01T00:00:00Z","root":"x","version":"v1","scorePct":33,` +
		`"compliant":1,"nonCompliant":2,"issues":0,"total":3,"digest":"sha256:old"}`
	if err := os.WriteFile(path, []byte(old+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hist, err := JSONLTrail{Path: path}.History()
	if err != nil {
		t.Fatalf("a record written before the field existed must still decode: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("history len=%d want 1", len(hist))
	}
	if hist[0].NotAssessed != 0 {
		t.Errorf("NotAssessed = %d, want 0 for a pre-field record", hist[0].NotAssessed)
	}
	if hist[0].ScorePct != 33 || hist[0].Total != 3 {
		t.Errorf("the rest of the record must survive unchanged: %+v", hist[0])
	}
}

func TestJSONLTrailMissingFile(t *testing.T) {
	hist, err := JSONLTrail{Path: filepath.Join(t.TempDir(), "nope.jsonl")}.History()
	if err != nil {
		t.Fatalf("missing trail should be empty, got %v", err)
	}
	if len(hist) != 0 {
		t.Errorf("want empty history, got %d", len(hist))
	}
}

func TestJSONLTrailMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(path, []byte("{\"scorePct\":1}\nnot-json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (JSONLTrail{Path: path}).History(); err == nil {
		t.Fatal("malformed line should error")
	}
}
