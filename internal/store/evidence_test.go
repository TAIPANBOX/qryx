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
