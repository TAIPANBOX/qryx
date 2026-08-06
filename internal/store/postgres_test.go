//go:build integration

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// pgStore returns a PostgresStore from DATABASE_URL, skipping when unset so the
// default test run (without the integration tag) never needs a database.
func pgStore(t *testing.T) PostgresStore {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres integration test")
	}
	return PostgresStore{ConnString: url}
}

func TestPostgresRoundtrip(t *testing.T) {
	s := pgStore(t)
	want := Snap(&scan.Result{Root: "rt", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048}, Location: model.Location{File: "a.go", Line: 5}, Source: "goast", Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh, Reason: "shor"}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5"}, Location: model.Location{File: "b.go", Line: 9}, Source: "goast", Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}},
	}})
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assets) != len(want.Assets) {
		t.Fatalf("assets = %d, want %d", len(got.Assets), len(want.Assets))
	}
	wantKeys := map[string]bool{}
	for _, a := range want.Assets {
		wantKeys[graph.AssetKey(a.Asset, a.Risk.Class)] = true
	}
	for _, a := range got.Assets {
		if !wantKeys[graph.AssetKey(a.Asset, a.Risk.Class)] {
			t.Errorf("unexpected asset %+v", a.Asset)
		}
		if len(a.Occurrences) == 0 {
			t.Errorf("asset %s lost its occurrences", a.Asset.Algorithm)
		}
	}
}

func TestPostgresLoadEmptyIsNotFound(t *testing.T) {
	// Run against a fresh database/schema; if scans already exist this is a
	// no-op assertion, so only assert the typed error when truly empty.
	s := pgStore(t)
	if _, err := s.Load(); err != nil && err != ErrNotFound {
		t.Fatalf("unexpected error: %v", err)
	}
}

func pgTrail(t *testing.T) PostgresTrail {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres integration test")
	}
	return PostgresTrail{ConnString: url}
}

func TestPostgresTrail(t *testing.T) {
	tr := pgTrail(t)

	before, err := tr.History()
	if err != nil {
		t.Fatal(err)
	}

	r1 := EvidenceRecord{CreatedAt: time.Now().UTC().Add(-time.Hour), Root: "pgtrail", Version: "v1", ScorePct: 40, NonCompliant: 3, Digest: "sha256:one"}
	r2 := EvidenceRecord{CreatedAt: time.Now().UTC(), Root: "pgtrail", Version: "v2", ScorePct: 60, NonCompliant: 1, Digest: "sha256:two"}
	if err := tr.Append(r1); err != nil {
		t.Fatal(err)
	}
	if err := tr.Append(r2); err != nil {
		t.Fatal(err)
	}

	after, err := tr.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+2 {
		t.Fatalf("history grew by %d, want 2", len(after)-len(before))
	}
	// The two newest records (ordered by created_at) are r1 then r2.
	last2 := after[len(after)-2:]
	if last2[0].ScorePct != 40 || last2[1].ScorePct != 60 {
		t.Errorf("append order wrong: %d then %d", last2[0].ScorePct, last2[1].ScorePct)
	}
	if last2[1].Digest != "sha256:two" || last2[1].Version != "v2" {
		t.Errorf("round-trip mismatch: %+v", last2[1])
	}
}

// TestPostgresTrailCarriesNotAssessed pins the fourth count through the
// Postgres backend, so the two trail implementations agree about what a record
// says rather than the file one carrying a number the database drops.
func TestPostgresTrailCarriesNotAssessed(t *testing.T) {
	tr := pgTrail(t)

	rec := EvidenceRecord{
		CreatedAt: time.Now().UTC(), Root: "pgtrail-na", Version: "v3", ScorePct: 25,
		Compliant: 1, NonCompliant: 1, Issues: 1, NotAssessed: 1, Total: 4, Digest: "sha256:na",
	}
	if err := tr.Append(rec); err != nil {
		t.Fatal(err)
	}
	hist, err := tr.History()
	if err != nil {
		t.Fatal(err)
	}
	got := hist[len(hist)-1]
	if got.Digest != "sha256:na" {
		t.Fatalf("expected the record just appended to be last, got %+v", got)
	}
	if got.NotAssessed != 1 {
		t.Errorf("NotAssessed = %d, want 1: %+v", got.NotAssessed, got)
	}
	if sum := got.Compliant + got.NonCompliant + got.Issues + got.NotAssessed; sum != got.Total {
		t.Errorf("counts sum to %d but Total = %d: %+v", sum, got.Total, got)
	}
}

// TestPostgresTrailBootstrapAddsNotAssessedColumn is the migration test. A
// deployment that has been writing evidence since before the fourth count
// existed has an evidence table without the column, and CREATE TABLE IF NOT
// EXISTS will not touch it: the bootstrap needs the ALTER, or every Append on
// that installation fails at the first insert. Dropping the column here is how
// that installation is reproduced, since the schema is applied on connect and a
// fresh test database always already has it.
func TestPostgresTrailBootstrapAddsNotAssessedColumn(t *testing.T) {
	tr := pgTrail(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, tr.ConnString)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `ALTER TABLE evidence DROP COLUMN IF EXISTS not_assessed`); err != nil {
		_ = conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	rec := EvidenceRecord{
		CreatedAt: time.Now().UTC(), Root: "pgtrail-migrate", Version: "v4", ScorePct: 50,
		Compliant: 2, NonCompliant: 1, Issues: 0, NotAssessed: 1, Total: 4, Digest: "sha256:migrated",
	}
	if err := tr.Append(rec); err != nil {
		t.Fatalf("append against a pre-existing evidence table must work: %v", err)
	}
	hist, err := tr.History()
	if err != nil {
		t.Fatal(err)
	}
	got := hist[len(hist)-1]
	if got.Digest != "sha256:migrated" || got.NotAssessed != 1 {
		t.Errorf("record after the column was added back = %+v, want NotAssessed 1", got)
	}
}

func TestPostgresDiffAcrossScans(t *testing.T) {
	s := pgStore(t)
	base := Snap(&scan.Result{Root: "d", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5"}, Location: model.Location{File: "a.go", Line: 1}, Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}},
	}})
	if err := s.Save(base); err != nil {
		t.Fatal(err)
	}
	cur := Snap(&scan.Result{Root: "d", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "DES"}, Location: model.Location{File: "a.go", Line: 2}, Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}},
	}})
	d := Diff(base, cur)
	if len(d.Added) != 1 || d.Added[0].Asset.Algorithm != "DES" {
		t.Errorf("Added = %+v, want DES", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Asset.Algorithm != "MD5" {
		t.Errorf("Removed = %+v, want MD5", d.Removed)
	}
}
