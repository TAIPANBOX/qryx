package store

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A snapshot path that exists but cannot be read as a file is an error, never
// ErrNotFound: the drift gates treat "not found" as "first run", and a baseline
// that is there but unreadable is not a first run.
func TestJSONStoreLoadErrorsAreNotNotFound(t *testing.T) {
	dir := t.TempDir()
	if _, err := (JSONStore{Path: dir}).Load(); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("a directory as a snapshot: got %v, want a read error that is not ErrNotFound", err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (JSONStore{Path: bad}).Load(); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("malformed JSON: got %v", err)
	}
	if _, err := (JSONStore{Path: filepath.Join(dir, "absent.json")}).Load(); !errors.Is(err, ErrNotFound) {
		t.Errorf("an absent snapshot must be ErrNotFound, got %v", err)
	}
}

// Save replaces an existing snapshot whole and leaves no temporary file
// behind; a directory that does not exist is an error.
func TestJSONStoreSaveReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "snap.json")
	s := JSONStore{Path: p}
	if err := s.Save(Snapshot{Root: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Snapshot{Root: "second"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil || got.Root != "second" {
		t.Fatalf("got %+v, %v; want the second snapshot", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only the snapshot", names)
	}
	if err := (JSONStore{Path: filepath.Join(dir, "missing", "snap.json")}).Save(Snapshot{}); err == nil {
		t.Error("saving into a directory that does not exist returned no error")
	}
}

// A missing trail is an empty history; a trail that cannot be read, or one
// with a line past the reader's limit, is an error rather than a shorter
// history. Blank lines are not records.
func TestJSONLTrailErrors(t *testing.T) {
	dir := t.TempDir()
	if recs, err := (JSONLTrail{Path: filepath.Join(dir, "absent.jsonl")}).History(); err != nil || recs != nil {
		t.Errorf("absent trail: got %v, %v", recs, err)
	}
	if _, err := (JSONLTrail{Path: dir}).History(); err == nil {
		t.Error("a directory as a trail returned no error")
	}
	if err := (JSONLTrail{Path: filepath.Join(dir, "missing", "t.jsonl")}).Append(EvidenceRecord{}); err == nil {
		t.Error("appending into a directory that does not exist returned no error")
	}

	p := filepath.Join(dir, "t.jsonl")
	tr := JSONLTrail{Path: p}
	if err := tr.Append(EvidenceRecord{Root: "a", CreatedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n   \n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := tr.Append(EvidenceRecord{Root: "b"}); err != nil {
		t.Fatal(err)
	}
	recs, err := tr.History()
	if err != nil || len(recs) != 2 || recs[0].Root != "a" || recs[1].Root != "b" {
		t.Fatalf("got %+v, %v; want records a then b", recs, err)
	}

	long := filepath.Join(dir, "long.jsonl")
	if err := os.WriteFile(long, []byte(`{"root":"`+strings.Repeat("x", 1<<20)+`"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (JSONLTrail{Path: long}).History(); err == nil {
		t.Error("a line past the reader's limit was dropped silently instead of failing")
	}
}

// A Postgres target that cannot be reached is an error from every operation,
// and Load's error is not ErrNotFound: an unreachable database is not an empty
// one.
func TestPostgresUnreachableIsAnErrorEverywhere(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "postgres://qryx@" + l.Addr().String() + "/qryx?connect_timeout=2&sslmode=disable"
	l.Close()

	s := PostgresStore{ConnString: url}
	if err := s.Save(Snapshot{}); err == nil {
		t.Error("Save to an unreachable database returned no error")
	}
	if _, err := s.Load(); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Load from an unreachable database: got %v, want a connection error", err)
	}
	tr := PostgresTrail{ConnString: url}
	if err := tr.Append(EvidenceRecord{}); err == nil {
		t.Error("Append to an unreachable database returned no error")
	}
	if recs, err := tr.History(); err == nil {
		t.Errorf("History from an unreachable database returned %v and no error", recs)
	}
}
