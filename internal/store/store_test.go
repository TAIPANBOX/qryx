package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

func result(findings ...model.Finding) *scan.Result {
	return &scan.Result{Root: "x", Findings: findings}
}

func md5At(file string, line int) model.Finding {
	return model.Finding{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5"}, Location: model.Location{File: file, Line: line}, Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}}
}

func rsaAt(file string, line, bits int) model.Finding {
	return model.Finding{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: bits}, Location: model.Location{File: file, Line: line}, Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	s := JSONStore{Path: filepath.Join(t.TempDir(), "snap.json")}
	want := Snap(result(md5At("a.go", 1), rsaAt("b.go", 2, 2048)))
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
	if got.SchemaVersion != schemaVersion || got.Root != want.Root {
		t.Errorf("metadata mismatch: %+v", got)
	}
}

func TestLoadMissingReturnsErrNotFound(t *testing.T) {
	s := JSONStore{Path: filepath.Join(t.TempDir(), "absent.json")}
	if _, err := s.Load(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDiffAddedAndRemoved(t *testing.T) {
	base := Snap(result(md5At("a.go", 1), rsaAt("b.go", 2, 2048)))
	// Drop MD5, add a new RSA-1024.
	cur := Snap(result(rsaAt("b.go", 2, 2048), rsaAt("c.go", 9, 1024)))

	d := Diff(base, cur)
	if d.Empty() {
		t.Fatal("expected drift")
	}
	if len(d.Added) != 1 || d.Added[0].Asset.KeySize != 1024 {
		t.Errorf("Added = %+v, want one RSA-1024", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Asset.Algorithm != "MD5" {
		t.Errorf("Removed = %+v, want MD5", d.Removed)
	}
}

func TestDiffNoChange(t *testing.T) {
	snap := Snap(result(md5At("a.go", 1)))
	if !Diff(snap, snap).Empty() {
		t.Error("identical snapshots should have no drift")
	}
}
