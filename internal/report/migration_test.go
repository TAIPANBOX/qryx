package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

func TestMigrationPlanExcludesCompliantAndRanks(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		// critical weak, low agility (code)
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 1024, Primitive: model.PrimitiveSignature}, Location: model.Location{File: "a.go", Line: 1}, Source: "goast", Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityCritical}},
		// high severity quantum, high agility (kms) → quick win, should rank above lower-severity
		{Asset: model.Asset{Type: model.TypeKey, Algorithm: "ECDSA", Primitive: model.PrimitiveSignature}, Location: model.Location{File: "arn:k"}, Source: "aws-kms", Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}},
		// compliant — must be excluded
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "ML-KEM"}, Location: model.Location{File: "c.go", Line: 3}, Source: "goast", Risk: model.Risk{Class: model.RiskNone}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "SHA-256"}, Location: model.Location{File: "d.go", Line: 4}, Source: "goast", Risk: model.Risk{Class: model.RiskNone}},
	}}

	var buf bytes.Buffer
	if err := Migration(&buf, res); err != nil {
		t.Fatal(err)
	}
	var rep migrationReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if rep.Summary.ToMigrate != 2 {
		t.Fatalf("toMigrate=%d want 2 (ML-KEM, SHA-256 excluded)", rep.Summary.ToMigrate)
	}
	// Critical RSA-1024 must be priority 1 (highest severity).
	if rep.Plan[0].Algorithm != "RSA-1024" || rep.Plan[0].Priority != 1 {
		t.Errorf("priority 1 = %s, want RSA-1024", rep.Plan[0].Algorithm)
	}
	if rep.Plan[0].Target != "ML-DSA (FIPS 204)" {
		t.Errorf("RSA-1024 target=%q", rep.Plan[0].Target)
	}
	// ECDSA from KMS is a quick win.
	if rep.Summary.QuickWins != 1 {
		t.Errorf("quickWins=%d want 1", rep.Summary.QuickWins)
	}
	for _, s := range rep.Plan {
		if s.Algorithm == "ECDSA" && s.Agility != "high" {
			t.Errorf("ECDSA from KMS agility=%q want high", s.Agility)
		}
	}
}
