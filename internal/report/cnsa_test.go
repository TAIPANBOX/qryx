package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

func makeNode(algo string, keySize int, riskClass model.RiskClass, sev model.Severity) graph.AssetNode {
	return graph.AssetNode{
		Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: algo, KeySize: keySize},
		Risk:  model.Risk{Class: riskClass, Severity: sev},
		Occurrences: []graph.Occurrence{
			{Location: model.Location{File: "test.go", Line: 1}},
		},
	}
}

func TestCnsaStatusClassification(t *testing.T) {
	tests := []struct {
		node         graph.AssetNode
		wantStatus   string
		wantDeadline string
	}{
		{makeNode("RSA", 2048, model.RiskQuantumVulnerable, model.SeverityHigh), "non-compliant", "2030"},
		{makeNode("ECDSA", 0, model.RiskQuantumVulnerable, model.SeverityHigh), "non-compliant", "2030"},
		{makeNode("MD5", 0, model.RiskWeak, model.SeverityHigh), "non-compliant", "immediate"},
		{makeNode("SHA-1", 0, model.RiskWeak, model.SeverityHigh), "non-compliant", "immediate"},
		{makeNode("ML-KEM", 0, model.RiskNone, model.SeverityNone), "compliant", "n/a"},
		{makeNode("ML-DSA", 0, model.RiskNone, model.SeverityNone), "compliant", "n/a"},
		{makeNode("AES", 256, model.RiskNone, model.SeverityNone), "compliant", "n/a"},
		{makeNode("SHA-512", 0, model.RiskNone, model.SeverityNone), "compliant", "n/a"},
	}
	for _, tc := range tests {
		t.Run(tc.node.Asset.Algorithm, func(t *testing.T) {
			e := cnsaStatus(tc.node)
			if e.Status != tc.wantStatus {
				t.Errorf("status=%q want %q", e.Status, tc.wantStatus)
			}
			if e.Deadline != tc.wantDeadline {
				t.Errorf("deadline=%q want %q", e.Deadline, tc.wantDeadline)
			}
		})
	}
}

func TestCNSAJSONOutput(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048}, Location: model.Location{File: "a.go", Line: 5}, Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5"}, Location: model.Location{File: "b.go", Line: 9}, Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "ML-KEM"}, Location: model.Location{File: "c.go", Line: 3}, Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}},
	}}

	var buf bytes.Buffer
	if err := CNSA(&buf, res); err != nil {
		t.Fatal(err)
	}
	var rep cnsaReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rep.Standard != "CNSA 2.0" {
		t.Errorf("standard=%q", rep.Standard)
	}
	if rep.Summary.NonCompliant != 2 {
		t.Errorf("nonCompliant=%d want 2", rep.Summary.NonCompliant)
	}
	if rep.Summary.Compliant != 1 {
		t.Errorf("compliant=%d want 1", rep.Summary.Compliant)
	}
}

// TestCNSAJSONOutputSurfacesBothRisksOnExpiredQuantumVulnerableCert pins the
// graph dedup bug at the report level: a certificate that is both
// quantum-vulnerable and expired must produce two entries in the CNSA report
// — a "non-compliant"/2030 entry for the algorithm and an "issue"/immediate
// entry for the expiry — not just one. A CI gate on `--policy cnsa
// --forbid-expired` (or reading this report) must be able to see the expiry;
// before the fix it was silently dropped by the graph's asset dedup.
func TestCNSAJSONOutputSurfacesBothRisksOnExpiredQuantumVulnerableCert(t *testing.T) {
	cert := model.Asset{Type: model.TypeCertificate, Algorithm: "RSA", KeySize: 2048}
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{
			Asset:    cert,
			Location: model.Location{File: "expired.badssl.com:443"},
			Source:   "tls-probe",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
		},
		{
			Asset:    cert,
			Location: model.Location{File: "expired.badssl.com:443"},
			Source:   "tls-probe",
			Risk:     model.Risk{Class: model.RiskExpired, Severity: model.SeverityHigh},
		},
	}}

	var buf bytes.Buffer
	if err := CNSA(&buf, res); err != nil {
		t.Fatal(err)
	}
	var rep cnsaReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(rep.Assets) != 2 {
		t.Fatalf("got %d asset entries, want 2 (quantum-vulnerable + expired): %+v", len(rep.Assets), rep.Assets)
	}

	var sawQuantum, sawExpired bool
	for _, a := range rep.Assets {
		if a.Type != string(model.TypeCertificate) || a.Algorithm != "RSA-2048" {
			t.Errorf("unexpected asset entry: %+v", a)
			continue
		}
		switch {
		case a.Status == "non-compliant" && a.Deadline == "2030":
			sawQuantum = true
		case a.Status == "issue" && a.Deadline == "immediate":
			sawExpired = true
		}
	}
	if !sawQuantum {
		t.Errorf("quantum-vulnerable entry missing from report: %+v", rep.Assets)
	}
	if !sawExpired {
		t.Errorf("expired entry missing from report — dedup dropped it: %+v", rep.Assets)
	}
}

func TestCNSAHTMLOutput(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA"}, Location: model.Location{File: "a.go", Line: 1}, Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}},
	}}
	var buf bytes.Buffer
	if err := CNSAHTML(&buf, res); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"CNSA 2.0", "<!DOCTYPE html>", "Non-compliant", "RSA"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}
