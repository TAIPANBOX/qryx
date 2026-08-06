package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
	"github.com/TAIPANBOX/qryx/internal/scan/detectors"
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

// TestUnknownSizeAESReachesTheMigrationPlan measures the defect where it is
// published, through the real detectors over the real fixture rather than
// hand-built findings, which would only pin what this test believes the
// detectors produce.
//
// testdata/aes-unknown-size holds three shapes that yield a sizeless AES asset
// in the field: an Azure Key Vault `oct` key in Terraform, whose length
// genuinely cannot be read from public metadata, and a rust `Aes128Gcm` and a
// node `createCipheriv('aes-128-cbc', ...)`, whose length is sitting in the
// matched text and is still not read, because both patterns anchor on the
// cipher name.
//
// Before this fix that tree produced `"toMigrate": 0` and a null plan: three
// AES occurrences, two of them on source lines that say 128, and a migration
// plan telling the reader there was nothing to migrate.
func TestUnknownSizeAESReachesTheMigrationPlan(t *testing.T) {
	res, err := scan.New(detectors.Default()...).Scan("../../testdata/aes-unknown-size")
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Migration(&buf, res); err != nil {
		t.Fatal(err)
	}
	var rep migrationReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	var aes []migrationStep
	for _, s := range rep.Plan {
		if strings.HasPrefix(s.Algorithm, "AES") {
			aes = append(aes, s)
		}
	}
	if len(aes) == 0 {
		t.Fatalf("no AES entry in the plan for a tree whose only cryptography is AES of unread size; toMigrate=%d", rep.Summary.ToMigrate)
	}
	if rep.Summary.ToMigrate != len(rep.Plan) {
		t.Errorf("toMigrate=%d but the plan has %d entries", rep.Summary.ToMigrate, len(rep.Plan))
	}
	for _, s := range aes {
		if s.Target != "AES-256-GCM" {
			t.Errorf("%s target=%q, want AES-256-GCM", s.Algorithm, s.Target)
		}
		// The entry is only worth listing if it says why it is listed: the
		// operator has to know this is "go read the key length" and not "this
		// key is known to be short".
		if !saysSizeWasNotRead(s.Rationale) {
			t.Errorf("%s rationale does not say the size was never read: %q", s.Algorithm, s.Rationale)
		}
		if len(s.Locations) == 0 {
			t.Errorf("%s has no location to go and check", s.Algorithm)
		}
	}
}

// saysSizeWasNotRead mirrors the assertion in internal/agility's own suite: the
// rationale must admit the key size was never established, in any phrasing.
func saysSizeWasNotRead(s string) bool {
	l := strings.ToLower(s)
	if !strings.Contains(l, "size") && !strings.Contains(l, "length") {
		return false
	}
	for _, marker := range []string{"could not", "did not", "not determine", "never read", "unknown", "not established"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}
