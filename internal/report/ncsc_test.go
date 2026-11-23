package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
	"github.com/TAIPANBOX/qryx/internal/store"
)

// TestNCSCJSONOutput golden-tests the report shape against a fixture that has
// one finding in each risk class the report cares about: quantum-vulnerable
// (twice: one plain-code RSA, one externally-facing/long-lived ECDH), weak
// (MD5), and safe/post-quantum (ML-KEM).
func TestNCSCJSONOutput(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		// Quantum-vulnerable, code-only: not externally-facing, not long-lived
		// (Primitive unset), so excluded from the 2031 highest-priority subset.
		{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048},
			Location: model.Location{File: "a.go", Line: 5},
			Source:   "goast",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
		},
		// Quantum-vulnerable, ACM certificate (externally-facing) AND
		// key-exchange (long-lived-data), so included in the 2031 subset.
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
	if err := NCSC(&buf, res, NCSCBaseline{}); err != nil {
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
	// No baseline: migrated is not measured (nil, JSON null), never a 0 that
	// reads as a measurement. Remaining is this scan's own count.
	if rep.Priority2031.Migrated != nil || rep.Priority2031.MigratedMeasured {
		t.Errorf("migrated = %v (measured %v) with no baseline, want nil and not measured", rep.Priority2031.Migrated, rep.Priority2031.MigratedMeasured)
	}
	if !strings.Contains(buf.String(), `"migratedCount": null`) {
		t.Error(`the JSON does not carry "migratedCount": null with no baseline`)
	}
	if rep.Priority2031.Remaining != 1 {
		t.Errorf("remaining = %d, want 1", rep.Priority2031.Remaining)
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
			// (buildNCSC/graph.Build never call risk.Classify; they trust
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
			rep := buildNCSC(res, NCSCBaseline{})
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
	if err := NCSCHTML(&buf, res, NCSCBaseline{}); err != nil {
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
	rep := buildNCSC(res, NCSCBaseline{})
	if rep.Discovery2028.TotalInventoried != 0 {
		t.Errorf("TotalInventoried = %d, want 0 (ai-usage excluded)", rep.Discovery2028.TotalInventoried)
	}
	if rep.Discovery2028.Verdict != verdictNotStarted {
		t.Errorf("Discovery2028.Verdict = %q, want %q (a crypto-empty scan must not read on-track just because ai-usage findings exist)", rep.Discovery2028.Verdict, verdictNotStarted)
	}
}

func TestNCSCHighestPriorityCriteriaDocumented(t *testing.T) {
	res := &scan.Result{Root: "test"}
	rep := buildNCSC(res, NCSCBaseline{})
	if rep.Priority2031.Criteria == "" {
		t.Error("Priority2031.Criteria must document the highest-priority definition")
	}
}

// An SSH host key is read off a live network endpoint, so it is as externally
// facing as a certificate the TLS probe reads: a quantum-vulnerable one lands
// in the 2031 highest-priority set, and the probe has its own coverage bucket.
func TestNCSCCountsAnSSHHostKeyAsExternallyFacing(t *testing.T) {
	res := &scan.Result{Root: "ssh://router:22", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "Ed25519", Primitive: model.PrimitiveSignature}, Location: model.Location{File: "router:22"}, Source: "ssh-probe", Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityMedium}},
	}}
	rep := buildNCSC(res, NCSCBaseline{})
	if rep.Priority2031.Count != 1 {
		t.Errorf("highest-priority count = %d, want 1: a host key read off the wire is externally facing", rep.Priority2031.Count)
	}
	if got := rep.Discovery2028.CoverageBySource["ssh"]; got != 1 {
		t.Errorf("coverage %v, want one occurrence in the ssh bucket", rep.Discovery2028.CoverageBySource)
	}
}

// @decided 2026-11-23: migrated counts only an asset that left the asset graph
// altogether. One that is still there under the same identity but no longer
// meets the 2031 criteria (its live endpoint was migrated while the same
// algorithm stays in code) has not been migrated, and is not counted, because
// the algorithm is still in the estate.
func TestMeasureMigratedCountsOnlyAssetsGoneFromTheGraph(t *testing.T) {
	kex := model.Finding{
		Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "ECDH", Primitive: model.PrimitiveKeyExch},
		Location: model.Location{File: "tls:example:443"},
		Source:   "tls-probe",
		Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
	}
	rsa := model.Finding{
		Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048},
		Location: model.Location{File: "tls:example:443"},
		Source:   "tls-probe",
		Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
	}
	base := store.Snapshot{SchemaVersion: store.SchemaVersion, Root: "r", Assets: graph.Build([]model.Finding{kex, rsa})}

	// Now: the key exchange is gone; RSA-2048 is still there, but only in code,
	// where it is neither externally facing nor long-lived data.
	rsaInCode := rsa
	rsaInCode.Location = model.Location{File: "a.go", Line: 3}
	rsaInCode.Source = "goast"
	res := &scan.Result{Root: "r", Findings: []model.Finding{rsaInCode}}

	rep := buildNCSC(res, NCSCBaseline{Snapshot: &base})
	if !rep.Priority2031.MigratedMeasured || rep.Priority2031.Migrated == nil {
		t.Fatalf("not measured against a like-for-like baseline: %s", rep.Priority2031.MigratedBasis)
	}
	if got := *rep.Priority2031.Migrated; got != 1 {
		t.Errorf("migrated = %d, want 1 (the key exchange, not RSA)", got)
	}
	if len(rep.Priority2031.MigratedFindings) != 1 || rep.Priority2031.MigratedFindings[0].Algorithm != "ECDH" {
		t.Errorf("migrated findings = %+v, want ECDH alone", rep.Priority2031.MigratedFindings)
	}
	if !strings.Contains(rep.Priority2031.MigratedBasis, "1 of the 2 highest-priority assets") {
		t.Errorf("basis %q does not state 1 of 2", rep.Priority2031.MigratedBasis)
	}
}

// Each reason a baseline is not measured against says so in its own words, in
// the report package itself and not only through the CLI.
func TestMeasureMigratedSaysWhyItDidNotMeasure(t *testing.T) {
	ok := store.Snapshot{SchemaVersion: store.SchemaVersion, Root: "r"}
	future := store.Snapshot{SchemaVersion: store.SchemaVersion + 1, Root: "r"}
	other := store.Snapshot{SchemaVersion: store.SchemaVersion, Root: "elsewhere"}
	cases := []struct {
		name     string
		base     NCSCBaseline
		measured bool
		words    string
	}{
		{"no baseline", NCSCBaseline{}, false, "no --baseline"},
		{"not found", NCSCBaseline{NotFound: true}, false, "not found"},
		{"another schema version", NCSCBaseline{Snapshot: &future}, false, "schemaVersion 2"},
		{"another target", NCSCBaseline{Snapshot: &other}, false, `another target ("elsewhere"`},
		{"same target, no time recorded", NCSCBaseline{Snapshot: &ok}, true, "taken at an unrecorded time: 0 of the 0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, measured, basis := measureMigrated(nil, "r", c.base)
			if measured != c.measured || !strings.Contains(basis, c.words) {
				t.Errorf("measured %v, basis %q; want measured %v and %q", measured, basis, c.measured, c.words)
			}
			if !c.measured && (got != nil || !strings.HasPrefix(basis, "not measured")) {
				t.Errorf("an unmeasured result returned %d assets and basis %q", len(got), basis)
			}
		})
	}
}

// Migrated assets are listed most severe first, then by name, then by full
// identity, so the same baseline renders the same list on every run (invariant
// 8: never an order taken from a map).
func TestMeasureMigratedListsTheSameOrderEveryRun(t *testing.T) {
	mk := func(alg string, size int, sev model.Severity) model.Finding {
		return model.Finding{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: alg, KeySize: size, Primitive: model.PrimitiveKeyExch},
			Location: model.Location{File: "tls:h:443"},
			Source:   "tls-probe",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: sev},
		}
	}
	findings := []model.Finding{
		mk("RSA", 2048, model.SeverityMedium),
		mk("ECDH", 0, model.SeverityMedium),
		mk("DH", 2048, model.SeverityCritical),
	}
	// Same algorithm name, different type: equal on severity and name, so only
	// the full identity can order them.
	key := mk("DH", 2048, model.SeverityCritical)
	key.Asset.Type = model.TypeKey
	findings = append(findings, key)

	created := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		// Feed the baseline in a different order each time.
		rot := append(append([]model.Finding{}, findings[i%len(findings):]...), findings[:i%len(findings)]...)
		base := store.Snapshot{SchemaVersion: store.SchemaVersion, Root: "r", CreatedAt: created, Assets: graph.Build(rot)}
		got, measured, basis := measureMigrated(nil, "r", NCSCBaseline{Snapshot: &base})
		if !measured || len(got) != 4 {
			t.Fatalf("measured %v, %d assets (%s), want 4", measured, len(got), basis)
		}
		var order []string
		for _, n := range got {
			order = append(order, string(n.Asset.Type)+":"+assetName(n))
		}
		want := "algorithm:DH-2048 key:DH-2048 algorithm:ECDH algorithm:RSA-2048"
		if strings.Join(order, " ") != want {
			t.Errorf("rotation %d: order %v, want %s", i, order, want)
		}
		if !strings.Contains(basis, "taken on 2026-11-01T09:00:00Z: 4 of the 4") {
			t.Errorf("basis %q does not name when the baseline was taken", basis)
		}
	}
}
