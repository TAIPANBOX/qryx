package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/agentstack"
	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
	"github.com/TAIPANBOX/qryx/internal/scan"
	"github.com/TAIPANBOX/qryx/internal/scan/detectors"
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

// TestCnsaStatusContextRiskWinsOverAlgorithmCompliance pins the field-ordering
// bug in cnsaStatus: the algorithm switch (MLKEM/MLDSA/SLHDSA, AES,
// SHA-384/512) used to return before n.Risk.Class was ever consulted, so a
// node carrying a real context risk (expired/hardcoded/misconfigured) on an
// otherwise CNSA-approved algorithm was silently graded "compliant". Concrete
// case: an expired Azure Key Vault symmetric key arrives as
// {Algorithm:"AES", KeySize:0, Risk.Class:RiskExpired} (Azure oct/HSM keys
// never expose a size): the AES branch's KeySize==0 path used to return
// "compliant" before the expiry was ever checked, corrupting `--format cnsa`,
// `cnsa-html`, `evidence`, `dashboard`, and the signed evidence trail. A
// context risk must always win over algorithm compliance.
func TestCnsaStatusContextRiskWinsOverAlgorithmCompliance(t *testing.T) {
	tests := []struct {
		name         string
		node         graph.AssetNode
		wantStatus   string
		wantDeadline string
	}{
		// The bug: an expired AES key (Azure oct/HSM, no key size exposed)
		// must report the expiry, not fall through to "compliant".
		{"expired AES key, no key size (Azure oct/HSM)", makeNode("AES", 0, model.RiskExpired, model.SeverityHigh), "issue", "immediate"},
		// Same trap, other context-risk classes and another CNSA-approved algorithm.
		{"hardcoded AES-256 key", makeNode("AES", 256, model.RiskHardcoded, model.SeverityHigh), "issue", "immediate"},
		{"misconfigured ML-KEM context", makeNode("ML-KEM", 0, model.RiskMisconfig, model.SeverityHigh), "issue", "immediate"},
		// Positive controls: no context risk (RiskNone) must still fall
		// through to algorithm+size grading, unaffected by the reorder.
		{"compliant AES-256, no context risk", makeNode("AES", 256, model.RiskNone, model.SeverityNone), "compliant", "n/a"},
		{"non-compliant AES-128 on size, no context risk", makeNode("AES", 128, model.RiskNone, model.SeverityNone), "non-compliant", "immediate"},
		{"compliant ML-KEM, no context risk", makeNode("ML-KEM", 0, model.RiskNone, model.SeverityNone), "compliant", "n/a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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

// TestCnsaMisconfigRemediationFollowsTheFinding pins that the remediation text
// is chosen by what the finding is, not only by its risk class. cnsaStatus
// branched on n.Risk.Class alone, so every misconfig finding was told to
// "enforce TLS 1.3 per CNSA 2.0" -- including an Agent Passport with no
// attestation method and an agent-event stream with no prev_hash chain, which
// are the two findings `qryx agents` exists to produce and neither of which
// has anything to do with TLS.
func TestCnsaMisconfigRemediationFollowsTheFinding(t *testing.T) {
	tests := []struct {
		name    string
		node    graph.AssetNode
		want    string // substring the action must contain
		notWant string // substring the action must not contain
	}{
		{
			name:    "passport with no attestation method",
			node:    misconfigNode(model.TypeProtocol, "no-attestation", "agent identity has no cryptographic attestation"),
			want:    "attestation",
			notWant: "TLS 1.3",
		},
		{
			name:    "event stream with no prev_hash chain",
			node:    misconfigNode(model.TypeProtocol, "no-hash-chain", "agent event stream is not tamper-evident (no hash chain)"),
			want:    "prev_hash",
			notWant: "TLS 1.3",
		},
		{
			name: "real TLS misconfiguration from the config detector",
			node: misconfigNode(model.TypeProtocol, "TLS 1.0", "TLS 1.0 is deprecated"),
			want: "TLS 1.3",
		},
		{
			name: "real TLS misconfiguration from a live probe",
			node: misconfigNode(model.TypeProtocol, "TLS", "TLS 1.1 is deprecated"),
			want: "TLS 1.3",
		},
		{
			name: "legacy SSL from a server config",
			node: misconfigNode(model.TypeProtocol, "SSL 3.0", "SSL 3.0 is broken (POODLE)"),
			want: "TLS 1.3",
		},
		{
			// The same trap one connector later: a misconfig this report has
			// never seen must not inherit the TLS line by default.
			name:    "a misconfiguration this report has no rule for",
			node:    misconfigNode(model.TypeKey, "kms-key-rotation-disabled", "automatic key rotation is off"),
			notWant: "TLS 1.3",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := cnsaStatus(tc.node)
			if e.Status != "issue" {
				t.Fatalf("status=%q want %q", e.Status, "issue")
			}
			if tc.want != "" && !strings.Contains(e.Action, tc.want) {
				t.Errorf("action %q does not mention %q", e.Action, tc.want)
			}
			if tc.notWant != "" && strings.Contains(e.Action, tc.notWant) {
				t.Errorf("action %q wrongly prescribes %q", e.Action, tc.notWant)
			}
		})
	}
}

// misconfigNode builds a context-risk node the way a connector emits one: the
// risk class is set by the detector, not derived from the algorithm.
func misconfigNode(typ model.AssetType, algo, reason string) graph.AssetNode {
	return graph.AssetNode{
		Asset:       model.Asset{Type: typ, Algorithm: algo},
		Risk:        model.Risk{Class: model.RiskMisconfig, Severity: model.SeverityMedium, Reason: reason},
		Occurrences: []graph.Occurrence{{Location: model.Location{File: "x"}, Source: "agentstack"}},
	}
}

// TestCnsaRemediationForRealAgentstackFindings runs the real connector over
// the real fixtures, so a rename on either side of this contract fails here:
// internal/agentstack decides the algorithm strings ("no-attestation",
// "no-hash-chain") and internal/report keys the remediation on them.
func TestCnsaRemediationForRealAgentstackFindings(t *testing.T) {
	findings, err := agentstack.Scan(filepath.Join("..", "agentstack", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	res := &scan.Result{Root: "agents://testdata", Findings: risk.Apply(findings)}

	var buf bytes.Buffer
	if err := CNSA(&buf, res); err != nil {
		t.Fatal(err)
	}
	var rep cnsaReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	want := map[string]string{"no-attestation": "attestation", "no-hash-chain": "prev_hash"}
	seen := map[string]bool{}
	for _, a := range rep.Assets {
		w, ok := want[a.Algorithm]
		if !ok {
			continue
		}
		seen[a.Algorithm] = true
		if !strings.Contains(a.Action, w) {
			t.Errorf("%s: action %q does not mention %q", a.Algorithm, a.Action, w)
		}
		if strings.Contains(a.Action, "TLS 1.3") {
			t.Errorf("%s: the compliance pack tells an operator to %q", a.Algorithm, a.Action)
		}
	}
	for algo := range want {
		if !seen[algo] {
			t.Errorf("no %q entry in the CNSA report: %+v", algo, rep.Assets)
		}
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

// TestCNSAExcludesNonCryptographicAssetTypes pins that an ai-usage finding
// (model.TypeAIModel) never counts toward the CNSA 2.0 audit: it is not a
// cryptography question, so it must not be graded "compliant" (which would
// misleadingly imply CNSA 2.0 was consulted and found no issue) or dilute
// the summary counts. A real, non-compliant MD5 finding alongside it must
// still be reported normally.
func TestCNSAExcludesNonCryptographicAssetTypes(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5"}, Location: model.Location{File: "a.go", Line: 1}, Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}},
		{Asset: model.Asset{Type: model.TypeAIModel, Algorithm: "Anthropic SDK (python)", Primitive: model.PrimitiveUnknown}, Location: model.Location{File: "requirements.txt", Line: 3}, Source: "aiusage", Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityInfo}},
	}}

	var buf bytes.Buffer
	if err := CNSA(&buf, res); err != nil {
		t.Fatal(err)
	}
	var rep cnsaReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rep.Summary.Total != 1 {
		t.Fatalf("total=%d want 1 (ai-usage excluded)", rep.Summary.Total)
	}
	if rep.Summary.NonCompliant != 1 || rep.Summary.Compliant != 0 {
		t.Errorf("compliant=%d nonCompliant=%d, want 0/1", rep.Summary.Compliant, rep.Summary.NonCompliant)
	}
	if len(rep.Assets) != 1 || rep.Assets[0].Algorithm != "MD5" {
		t.Errorf("assets=%+v, want only MD5", rep.Assets)
	}
}

// TestCnsaStatusUnrecognisedAlgorithmIsNotAssessed pins the third state. The
// final branch of cnsaStatus used to return "compliant" with "No CNSA 2.0
// restriction identified" for every RiskNone asset the algorithm switch did
// not recognize, which is not what CNSA 2.0 says about any of them: SHA-256 is
// not on the CNSA 2.0 list, and bcrypt, HMAC, ChaCha20, X509, OIDC and the
// enclave-key pseudo-asset `qryx agents` emits were never graded at all. The
// compliance score is compliant*100/total, so a scan full of crypto this tool
// does not recognize scored high, and that number is what `--format evidence`
// signs and what `qryx trend --fail-on-regression` gates on.
//
// Not knowing is its own answer, and it has to be visible as one.
func TestCnsaStatusUnrecognisedAlgorithmIsNotAssessed(t *testing.T) {
	tests := []struct {
		algo       string
		keySize    int
		wantStatus string
	}{
		// Never graded by any rule in cnsaStatus: these must not read as a pass.
		{"SHA-256", 0, "not-assessed"},
		{"bcrypt", 0, "not-assessed"},
		{"HMAC", 0, "not-assessed"},
		{"ChaCha20", 0, "not-assessed"},
		{"X509", 0, "not-assessed"},         // agentstack mtls-cert/spiffe-svid passport
		{"OIDC", 0, "not-assessed"},         // agentstack oidc passport
		{"enclave-key", 0, "not-assessed"},  // agentstack enclave-key passport
		{"SM2", 0, "not-assessed"},          // an algorithm risk.Classify does not know
		{"cryptography", 0, "not-assessed"}, // a dependency-manifest library name
		// Positive controls: the CNSA 2.0 suite itself still passes.
		{"ML-KEM", 0, "compliant"},
		{"ML-DSA", 0, "compliant"},
		{"SLH-DSA", 0, "compliant"},
		{"AES", 256, "compliant"},
		{"AES", 0, "compliant"},
		{"SHA-384", 0, "compliant"},
		{"SHA-512", 0, "compliant"},
	}
	for _, tc := range tests {
		t.Run(tc.algo, func(t *testing.T) {
			e := cnsaStatus(makeNode(tc.algo, tc.keySize, model.RiskNone, model.SeverityNone))
			if e.Status != tc.wantStatus {
				t.Errorf("status=%q want %q (action was %q)", e.Status, tc.wantStatus, e.Action)
			}
		})
	}
}

// TestCNSAScoreDoesNotFlatterUnrecognisedCrypto is the same defect measured
// where it is published: the percentage. A scan whose entire inventory is
// crypto this tool never graded must not report a high compliance score, and a
// scan that is genuinely CNSA 2.0 compliant must still report 100.
func TestCNSAScoreDoesNotFlatterUnrecognisedCrypto(t *testing.T) {
	unrecognised := &scan.Result{Root: "test", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "SHA-256", Primitive: model.PrimitiveHash},
			Location: model.Location{File: "a.py", Line: 3}, Source: "cryptocall",
			Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}},
	}}
	ev, err := buildEvidence(unrecognised, "test")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Summary.ScorePct == 100 {
		t.Errorf("a scan containing only SHA-256 scored %d%% CNSA 2.0 compliant; SHA-256 is not on the CNSA 2.0 list", ev.Summary.ScorePct)
	}
	if ev.Summary.Compliant != 0 {
		t.Errorf("compliant=%d want 0: nothing in this scan was graded compliant", ev.Summary.Compliant)
	}

	compliant := &scan.Result{Root: "test", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "ML-KEM", Primitive: model.PrimitiveKeyExch},
			Location: model.Location{File: "a.rs", Line: 1}, Source: "rust",
			Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "AES", KeySize: 256, Primitive: model.PrimitiveEncryption},
			Location: model.Location{File: "b.rs", Line: 2}, Source: "rust",
			Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "SHA-384", Primitive: model.PrimitiveHash},
			Location: model.Location{File: "c.rs", Line: 3}, Source: "rust",
			Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}},
	}}
	ev, err = buildEvidence(compliant, "test")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Summary.ScorePct != 100 {
		t.Errorf("a genuinely CNSA 2.0 compliant scan scored %d%%, want 100 (%+v)", ev.Summary.ScorePct, ev.Summary)
	}
}

// TestCNSAReportsAllFourCounts pins the split being visible rather than merely
// correct. A reader who cannot see how much of the inventory was never graded
// cannot judge the score: 60% compliant out of assets that were all assessed
// and 60% out of an inventory half of which nothing looked at are different
// facts. The counts are read by their wire names, so the JSON contract is what
// is pinned, not a Go field name.
func TestCNSAReportsAllFourCounts(t *testing.T) {
	res := &scan.Result{Root: "test", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "ML-KEM"}, Location: model.Location{File: "a.go", Line: 1},
			Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048}, Location: model.Location{File: "b.go", Line: 2},
			Risk: model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh}},
		{Asset: model.Asset{Type: model.TypeProtocol, Algorithm: "TLS 1.0"}, Location: model.Location{File: "c.conf", Line: 3},
			Risk: model.Risk{Class: model.RiskMisconfig, Severity: model.SeverityHigh}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "SHA-256"}, Location: model.Location{File: "d.py", Line: 4},
			Risk: model.Risk{Class: model.RiskNone, Severity: model.SeverityNone}},
	}}

	var buf bytes.Buffer
	if err := CNSA(&buf, res); err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Summary map[string]int `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &wire); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	want := map[string]int{"compliant": 1, "nonCompliant": 1, "issues": 1, "notAssessed": 1, "total": 4}
	for k, v := range want {
		got, ok := wire.Summary[k]
		if !ok {
			t.Errorf("cnsa summary has no %q count: %v", k, wire.Summary)
			continue
		}
		if got != v {
			t.Errorf("cnsa summary %s=%d want %d (%v)", k, got, v, wire.Summary)
		}
	}

	var evBuf bytes.Buffer
	if _, err := Evidence(&evBuf, res, "test", nil); err != nil {
		t.Fatal(err)
	}
	// A pointer, so a missing count reads differently from a zero one.
	var evWire struct {
		Summary struct {
			NotAssessed *int `json:"notAssessed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(evBuf.Bytes(), &evWire); err != nil {
		t.Fatalf("invalid evidence JSON: %v", err)
	}
	if evWire.Summary.NotAssessed == nil {
		t.Errorf("evidence summary has no notAssessed count: %s", evBuf.String())
	} else if *evWire.Summary.NotAssessed != 1 {
		t.Errorf("evidence summary notAssessed=%d want 1", *evWire.Summary.NotAssessed)
	}

	var htmlBuf bytes.Buffer
	if err := CNSAHTML(&htmlBuf, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(htmlBuf.String(), "not assessed") {
		t.Errorf("cnsa-html never says how many assets were not assessed")
	}

	var dashBuf bytes.Buffer
	if err := Dashboard(&dashBuf, res, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dashBuf.String(), "not assessed") {
		t.Errorf("dashboard never says how many assets were not assessed")
	}
}

// TestDependencyManifestStaysOutOfTheScoreAndTheMigrationSet is the same
// defect measured where it was published. A requirements.txt naming a crypto
// library used to arrive as an RSA quantum-vulnerable HIGH asset, so it was
// counted non-compliant by the CNSA audit, listed in the NCSC 2035 migration
// set, and given a migration plan entry telling the operator to move a line in
// a manifest to ML-KEM. It runs the real detector over a real file, because a
// hand-built finding would only pin what this test itself believes.
func TestDependencyManifestStaysOutOfTheScoreAndTheMigrationSet(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==3.0\ncryptography>=42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := scan.New(detectors.NewDeps()).Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(res.Findings), res.Findings)
	}

	var cnsaBuf bytes.Buffer
	if err := CNSA(&cnsaBuf, res); err != nil {
		t.Fatal(err)
	}
	var rep cnsaReport
	if err := json.Unmarshal(cnsaBuf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rep.Summary.NonCompliant != 0 {
		t.Errorf("nonCompliant=%d want 0: a manifest line is not a non-compliant algorithm (%+v)", rep.Summary.NonCompliant, rep.Assets)
	}
	if rep.Summary.NotAssessed != 1 {
		t.Errorf("notAssessed=%d want 1: the library is still in the inventory, ungraded (%+v)", rep.Summary.NotAssessed, rep.Assets)
	}

	var ncscBuf bytes.Buffer
	if err := NCSC(&ncscBuf, res); err != nil {
		t.Fatal(err)
	}
	var ncsc ncscReport
	if err := json.Unmarshal(ncscBuf.Bytes(), &ncsc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if ncsc.Full2035.Count != 0 || ncsc.Discovery2028.QuantumVulnerable != 0 {
		t.Errorf("NCSC has %d quantum-vulnerable asset(s) and %d in the 2035 set, want 0 and 0",
			ncsc.Discovery2028.QuantumVulnerable, ncsc.Full2035.Count)
	}
	if ncsc.Discovery2028.TotalInventoried != 1 {
		t.Errorf("totalInventoried=%d want 1: the dependency is still discovered, just not vulnerable", ncsc.Discovery2028.TotalInventoried)
	}

	var migBuf bytes.Buffer
	if err := Migration(&migBuf, res); err != nil {
		t.Fatal(err)
	}
	var mig migrationReport
	if err := json.Unmarshal(migBuf.Bytes(), &mig); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if mig.Summary.ToMigrate != 0 {
		t.Errorf("migration plan has %d step(s) for a dependency manifest: %+v", mig.Summary.ToMigrate, mig.Plan)
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
