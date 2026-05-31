package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
)

func node(algo string, size int, class model.RiskClass, sev model.Severity) graph.AssetNode {
	return graph.AssetNode{
		Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: algo, KeySize: size},
		Risk:  model.Risk{Class: class, Severity: sev},
		Occurrences: []graph.Occurrence{
			{Location: model.Location{File: "a.go", Line: 1}},
		},
	}
}

func rules(vs []Violation) map[string]bool {
	m := map[string]bool{}
	for _, v := range vs {
		m[v.Rule] = true
	}
	return m
}

func TestForbiddenAlgorithm(t *testing.T) {
	p := Policy{ForbidAlgorithms: []string{"MD5", "SHA1"}}
	vs := Evaluate(p, []graph.AssetNode{
		node("MD5", 0, model.RiskWeak, model.SeverityHigh),
		node("SHA-1", 0, model.RiskWeak, model.SeverityHigh),
		node("SHA-256", 0, model.RiskNone, model.SeverityNone),
	})
	if len(vs) != 2 {
		t.Fatalf("want 2 violations, got %d: %+v", len(vs), vs)
	}
	for _, v := range vs {
		if v.Rule != "forbidden-algorithm" {
			t.Errorf("rule=%q", v.Rule)
		}
	}
}

func TestMinRSABits(t *testing.T) {
	p := Policy{MinRSABits: 3072}
	vs := Evaluate(p, []graph.AssetNode{
		node("RSA", 1024, model.RiskWeak, model.SeverityCritical),
		node("RSA", 3072, model.RiskQuantumVulnerable, model.SeverityHigh),
	})
	if !rules(vs)["min-rsa-bits"] {
		t.Fatal("RSA-1024 should violate min-rsa-bits")
	}
	for _, v := range vs {
		if v.Asset == "RSA-3072" {
			t.Errorf("RSA-3072 must not violate min-rsa-bits: %+v", v)
		}
	}
}

func TestQuantumVulnerableOptIn(t *testing.T) {
	nodes := []graph.AssetNode{node("ECDSA", 0, model.RiskQuantumVulnerable, model.SeverityHigh)}

	if vs := Evaluate(Policy{}, nodes); len(vs) != 0 {
		t.Fatalf("quantum not forbidden by default, got %+v", vs)
	}
	if vs := Evaluate(Policy{ForbidQuantumVulnerable: true}, nodes); !rules(vs)["quantum-vulnerable"] {
		t.Fatal("ForbidQuantumVulnerable should flag ECDSA")
	}
}

func TestContextToggles(t *testing.T) {
	nodes := []graph.AssetNode{
		node("RSA", 2048, model.RiskHardcoded, model.SeverityCritical),
		node("RSA", 2048, model.RiskExpired, model.SeverityHigh),
		node("TLS 1.0", 0, model.RiskMisconfig, model.SeverityMedium),
	}
	if vs := Evaluate(Policy{}, nodes); len(vs) != 0 {
		t.Fatalf("nothing forbidden by default, got %+v", vs)
	}
	got := rules(Evaluate(Policy{ForbidHardcoded: true, ForbidExpired: true, ForbidMisconfig: true}, nodes))
	for _, r := range []string{"hardcoded", "expired", "misconfig"} {
		if !got[r] {
			t.Errorf("missing %s violation", r)
		}
	}
}

func TestMaxSeverity(t *testing.T) {
	p := Policy{MaxSeverity: "medium"}
	vs := Evaluate(p, []graph.AssetNode{
		node("RSA", 1024, model.RiskWeak, model.SeverityCritical),
		node("3DES", 0, model.RiskWeak, model.SeverityMedium),
		node("AES", 256, model.RiskNone, model.SeverityNone),
	})
	if !rules(vs)["max-severity"] {
		t.Fatal("critical asset should exceed medium max")
	}
	for _, v := range vs {
		if v.Rule == "max-severity" && v.Asset != "RSA-1024" {
			t.Errorf("only RSA-1024 exceeds medium, got %s", v.Asset)
		}
	}
}

func TestBuiltinCNSA(t *testing.T) {
	p, err := Load("cnsa")
	if err != nil {
		t.Fatal(err)
	}
	vs := Evaluate(p, []graph.AssetNode{
		node("MD5", 0, model.RiskWeak, model.SeverityHigh),
		node("RSA", 1024, model.RiskWeak, model.SeverityCritical),
		node("ECDSA", 0, model.RiskQuantumVulnerable, model.SeverityHigh),
		node("AES", 256, model.RiskNone, model.SeverityNone),
	})
	got := rules(vs)
	if !got["forbidden-algorithm"] || !got["min-rsa-bits"] {
		t.Errorf("cnsa should flag MD5 and RSA-1024: %+v", vs)
	}
	if got["quantum-vulnerable"] {
		t.Error("cnsa must not hard-fail quantum-vulnerable by default")
	}
}

func TestLoadFileAndErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	if err := os.WriteFile(path, []byte(`{"name":"custom","minRsaBits":4096}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "custom" || p.MinRSABits != 4096 {
		t.Errorf("loaded %+v", p)
	}

	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file should error")
	}

	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"maxSeverity":"nonsense"}`), 0o644)
	if _, err := Load(bad); err == nil {
		t.Error("invalid maxSeverity should error")
	}
}

func TestEmptyPolicyNoViolations(t *testing.T) {
	vs := Evaluate(Policy{}, []graph.AssetNode{
		node("MD5", 0, model.RiskWeak, model.SeverityHigh),
		node("RSA", 512, model.RiskWeak, model.SeverityCritical),
	})
	if len(vs) != 0 {
		t.Fatalf("zero policy forbids nothing, got %+v", vs)
	}
}
