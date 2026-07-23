package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// TestNCSCJSONOutput golden-tests the report shape against a fixture that has
// one finding in each risk class the report cares about: quantum-vulnerable
// (twice — one plain-code RSA, one externally-facing/long-lived ECDH), weak
// (MD5), and safe/post-quantum (ML-KEM).
func TestNCSCJSONOutput(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		// Quantum-vulnerable, code-only: not externally-facing, not long-lived
		// (Primitive unset) — excluded from the 2031 highest-priority subset.
		{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048},
			Location: model.Location{File: "a.go", Line: 5},
			Source:   "goast",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
		},
		// Quantum-vulnerable, ACM certificate (externally-facing) AND
		// key-exchange (long-lived-data) — included in the 2031 subset.
		{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "ECDH", Primitive: model.PrimitiveKeyExch},
			Location: model.Location{File: "acm:cert-1"},
			Source:   "aws-acm",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
		},
		// Classically weak, not quantum-specific.
		{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5"},
			Location: model.Location{File: "b.go", Line: 9},
			Source:   "goast",
			Risk:     model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh},
		},
		// Post-quantum safe.
		{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "ML-KEM"},
			Location: model.Location{File: "c.go", Line: 3},
			Source:   "goast",
			Risk:     model.Risk{Class: model.RiskNone, Severity: model.SeverityNone},
		},
	}}

	var buf bytes.Buffer
	if err := NCSC(&buf, res); err != nil {
		t.Fatal(err)
	}
	var rep ncscReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if rep.Standard != ncscStandard {
		t.Errorf("standard = %q, want %q", rep.Standard, ncscStandard)
	}

	// 2028 discovery: all four assets inventoried, two quantum-vulnerable, plan
	// covers both (RSA and ECDH both have recognized agility migration targets).
	if rep.Discovery2028.TotalInventoried != 4 {
		t.Errorf("TotalInventoried = %d, want 4", rep.Discovery2028.TotalInventoried)
	}
	if rep.Discovery2028.QuantumVulnerable != 2 {
		t.Errorf("QuantumVulnerable = %d, want 2", rep.Discovery2028.QuantumVulnerable)
	}
	if !rep.Discovery2028.PlanExists {
		t.Error("PlanExists = false, want true (both RSA and ECDH have agility targets)")
	}
	if rep.Discovery2028.Verdict != verdictOnTrack {
		t.Errorf("Discovery2028.Verdict = %q, want %q", rep.Discovery2028.Verdict, verdictOnTrack)
	}
	if got, want := rep.Discovery2028.CoverageBySource["code"], 3; got != want {
		t.Errorf("coverage[code] = %d, want %d", got, want)
	}
	if got, want := rep.Discovery2028.CoverageBySource["certs"], 1; got != want {
		t.Errorf("coverage[certs] = %d, want %d", got, want)
	}

	// 2031 highest-priority: only the ECDH asset qualifies.
	if rep.Priority2031.Count != 1 {
		t.Fatalf("Priority2031.Count = %d, want 1", rep.Priority2031.Count)
	}
	if rep.Priority2031.Findings[0].Algorithm != "ECDH" {
		t.Errorf("Priority2031 finding = %q, want ECDH", rep.Priority2031.Findings[0].Algorithm)
	}
	if !rep.Priority2031.Findings[0].ExternallyFacing || !rep.Priority2031.Findings[0].LongLivedData {
		t.Error("ECDH finding should be both externally-facing and long-lived-data")
	}
	if rep.Priority2031.Migrated != 0 || rep.Priority2031.Remaining != 1 {
		t.Errorf("migrated/remaining = %d/%d, want 0/1", rep.Priority2031.Migrated, rep.Priority2031.Remaining)
	}
	// A highest-priority item is outstanding, so 2031 reads at-risk even though
	// discovery (2028) is on-track.
	if rep.Priority2031.Verdict != verdictAtRisk {
		t.Errorf("Priority2031.Verdict = %q, want %q", rep.Priority2031.Verdict, verdictAtRisk)
	}

	// 2035 full migration: both quantum-vulnerable assets remain.
	if rep.Full2035.Count != 2 {
		t.Errorf("Full2035.Count = %d, want 2", rep.Full2035.Count)
	}
	if rep.Full2035.Verdict != verdictAtRisk {
		t.Errorf("Full2035.Verdict = %q, want %q", rep.Full2035.Verdict, verdictAtRisk)
	}
}

// TestNCSCVerdicts exercises all three verdict branches (not-started,
// on-track, at-risk) for every milestone using three minimal fixtures.
func TestNCSCVerdicts(t *testing.T) {
	tests := []struct {
		name     string
		findings []model.Finding
		want     ncscVerdict
	}{
		{
			name:     "nothing scanned",
			findings: nil,
			want:     verdictNotStarted,
		},
		{
			name: "clean scan, no quantum-vulnerable crypto",
			findings: []model.Finding{
				{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "AES", KeySize: 256}, Location: model.Location{File: "a.go", Line: 1}, Source: "goast", Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}},
				{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "ML-KEM"}, Location: model.Location{File: "b.go", Line: 1}, Source: "goast", Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}},
			},
			want: verdictOnTrack,
		},
		{
			// SM2 (a real ECC-based signature algorithm, quantum-vulnerable via
			// Shor like any discrete-log scheme) is not in agility.target()'s
			// switch, so agility.Assess proposes no migration target for it and
			// no plan covers it. Risk is set directly on the finding here
			// (buildNCSC/graph.Build never call risk.Classify — they trust
			// Finding.Risk as scored upstream) specifically so this test stays
			// independent of which algorithms risk.Classify happens to flag;
			// it is also externally-facing (tls-probe), so it lands in the 2031
			// highest-priority subset too.
			name: "quantum-vulnerable asset with no migration plan",
			findings: []model.Finding{
				{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "SM2"}, Location: model.Location{File: "host:443"}, Source: "tls-probe", Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityMedium}},
			},
			want: verdictAtRisk,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := &scan.Result{Root: "test", Findings: tc.findings}
			rep := buildNCSC(res)
			if rep.Discovery2028.Verdict != tc.want {
				t.Errorf("Discovery2028.Verdict = %q, want %q", rep.Discovery2028.Verdict, tc.want)
			}
			if rep.Priority2031.Verdict != tc.want {
				t.Errorf("Priority2031.Verdict = %q, want %q", rep.Priority2031.Verdict, tc.want)
			}
			if rep.Full2035.Verdict != tc.want {
				t.Errorf("Full2035.Verdict = %q, want %q", rep.Full2035.Verdict, tc.want)
			}
		})
	}
}

func TestNCSCHTMLOutput(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048}, Location: model.Location{File: "a.go", Line: 1}, Source: "goast", Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}},
	}}
	var buf bytes.Buffer
	if err := NCSCHTML(&buf, res); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<!DOCTYPE html>", "NCSC PQC Migration Readiness Report", ncscStandard, "2028", "2031", "2035", "RSA-2048"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

// TestNCSCExcludesNonCryptographicAssetTypes pins that ai-usage findings
// (model.TypeAIModel) never enter this report's coverage/total counts or
// verdicts: this report is specifically about cryptography discovery and
// PQC migration, so a scan containing only AI-SDK usage and zero
// cryptography must read as "not-started", not "on-track": the verdict
// must not flip just because non-cryptographic findings existed.
func TestNCSCExcludesNonCryptographicAssetTypes(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{
			Asset:    model.Asset{Type: model.TypeAIModel, Algorithm: "OpenAI SDK (python)", Primitive: model.PrimitiveUnknown},
			Location: model.Location{File: "agent.py", Line: 2},
			Source:   "aiusage",
			Risk:     model.Risk{Class: model.RiskNone, Severity: model.SeverityInfo},
		},
	}}
	rep := buildNCSC(res)
	if rep.Discovery2028.TotalInventoried != 0 {
		t.Errorf("TotalInventoried = %d, want 0 (ai-usage excluded)", rep.Discovery2028.TotalInventoried)
	}
	if rep.Discovery2028.Verdict != verdictNotStarted {
		t.Errorf("Discovery2028.Verdict = %q, want %q (a crypto-empty scan must not read on-track just because ai-usage findings exist)", rep.Discovery2028.Verdict, verdictNotStarted)
	}
}

func TestNCSCHighestPriorityCriteriaDocumented(t *testing.T) {
	res := &scan.Result{Root: "test"}
	rep := buildNCSC(res)
	if rep.Priority2031.Criteria == "" {
		t.Error("Priority2031.Criteria must document the highest-priority definition")
	}
}
