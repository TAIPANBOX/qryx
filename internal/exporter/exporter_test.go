package exporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/policy"
)

func mustOpen(t *testing.T) (*Exporter, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.ndjson")
	e, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e, path
}

func readEvents(t *testing.T, path string) []event.Event {
	t.Helper()
	events, err := event.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func withAgentID(tags map[string]string, id string) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		out[k] = v
	}
	out["agent_id"] = id
	return out
}

// ------------------------------------------------------------------
// EmitFindings
// ------------------------------------------------------------------

func TestEmitFindingsSkipsNoAgentID(t *testing.T) {
	e, path := mustOpen(t)
	findings := []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5"}, Risk: model.Risk{Severity: model.SeverityHigh}}, // no Tags at all
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA"}, Tags: map[string]string{"owner": "team-x"}},     // owner but no agent_id
	}
	if err := e.EmitFindings(findings); err != nil {
		t.Fatal(err)
	}
	if got := readEvents(t, path); len(got) != 0 {
		t.Fatalf("events = %d, want 0 (no finding carried an agent_id)", len(got))
	}
}

func TestEmitFindingsEmitsForRealAgentID(t *testing.T) {
	e, path := mustOpen(t)
	findings := []model.Finding{
		{
			Asset:    model.Asset{Type: model.TypeCertificate, Algorithm: "X509"},
			Evidence: "agent agent://acme.example/bot attests via spiffe-svid",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
			Tags:     withAgentID(map[string]string{"owner": "team-x"}, "agent://acme.example/bot"),
		},
	}
	if err := e.EmitFindings(findings); err != nil {
		t.Fatal(err)
	}
	got := readEvents(t, path)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	ev := got[0]
	if ev.Schema != event.SchemaV01 {
		t.Errorf("schema = %q, want v0.1 (qryx is one of the original four)", ev.Schema)
	}
	if ev.Source != "qryx" {
		t.Errorf("source = %q, want qryx", ev.Source)
	}
	if ev.Type != TypeCryptoFinding {
		t.Errorf("type = %q, want %q", ev.Type, TypeCryptoFinding)
	}
	if ev.AgentID != "agent://acme.example/bot" {
		t.Errorf("agent_id = %q", ev.AgentID)
	}
	if ev.Severity != event.SeverityHigh {
		t.Errorf("severity = %q, want high", ev.Severity)
	}
	if ev.Data["algorithm"] != "X509" {
		t.Errorf("data.algorithm = %v", ev.Data["algorithm"])
	}
}

func TestEmitFindingsSeverityNoneFoldsToInfo(t *testing.T) {
	e, path := mustOpen(t)
	findings := []model.Finding{
		{
			Asset: model.Asset{Type: model.TypeKey, Algorithm: "enclave-key"},
			Risk:  model.Risk{Class: model.RiskNone, Severity: model.SeverityNone},
			Tags:  map[string]string{"agent_id": "agent://acme.example/bot"},
		},
	}
	if err := e.EmitFindings(findings); err != nil {
		t.Fatal(err)
	}
	got := readEvents(t, path)
	if len(got) != 1 || got[0].Severity != event.SeverityInfo {
		t.Fatalf("severity = %q, want info (SeverityNone has no envelope equivalent)", got[0].Severity)
	}
}

// ------------------------------------------------------------------
// EmitDrift
// ------------------------------------------------------------------

func TestEmitDriftSkipsNoAgentID(t *testing.T) {
	e, path := mustOpen(t)
	added := []graph.AssetNode{
		{Asset: model.Asset{Algorithm: "RSA"}, Risk: model.Risk{Severity: model.SeverityHigh}},
	}
	if err := e.EmitDrift(added); err != nil {
		t.Fatal(err)
	}
	if got := readEvents(t, path); len(got) != 0 {
		t.Fatalf("events = %d, want 0", len(got))
	}
}

func TestEmitDriftEmitsForRealAgentID(t *testing.T) {
	e, path := mustOpen(t)
	added := []graph.AssetNode{
		{
			Asset: model.Asset{Type: model.TypeCertificate, Algorithm: "X509"},
			Risk:  model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
			Tags:  map[string]string{"agent_id": "agent://acme.example/bot"},
		},
	}
	if err := e.EmitDrift(added); err != nil {
		t.Fatal(err)
	}
	got := readEvents(t, path)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	if got[0].Type != TypeCryptoDrift {
		t.Errorf("type = %q, want %q", got[0].Type, TypeCryptoDrift)
	}
	if got[0].Data["verdict"] != "new" {
		t.Errorf("data.verdict = %v", got[0].Data["verdict"])
	}
}

// ------------------------------------------------------------------
// EmitViolations
// ------------------------------------------------------------------

func TestEmitViolationsSkipsNoAgentID(t *testing.T) {
	e, path := mustOpen(t)
	violations := []policy.Violation{
		{Rule: "forbidden-algorithm", Asset: "RSA-1024", Severity: model.SeverityCritical},
	}
	if err := e.EmitViolations(violations); err != nil {
		t.Fatal(err)
	}
	if got := readEvents(t, path); len(got) != 0 {
		t.Fatalf("events = %d, want 0", len(got))
	}
}

func TestEmitViolationsEmitsForRealAgentID(t *testing.T) {
	e, path := mustOpen(t)
	violations := []policy.Violation{
		{
			Rule: "quantum-vulnerable", Asset: "RSA-2048", Severity: model.SeverityHigh,
			Message: "RSA-2048 is quantum-vulnerable and forbidden by policy",
			Tags:    map[string]string{"agent_id": "agent://acme.example/bot"},
		},
	}
	if err := e.EmitViolations(violations); err != nil {
		t.Fatal(err)
	}
	got := readEvents(t, path)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	if got[0].Type != TypePolicyViolation {
		t.Errorf("type = %q, want %q", got[0].Type, TypePolicyViolation)
	}
	if got[0].Data["rule"] != "quantum-vulnerable" {
		t.Errorf("data.rule = %v", got[0].Data["rule"])
	}
}

// ------------------------------------------------------------------
// EmitEvidenceSigned
// ------------------------------------------------------------------

func TestEmitEvidenceSignedOnePerDistinctAgent(t *testing.T) {
	e, path := mustOpen(t)
	findings := []model.Finding{
		{Tags: map[string]string{"agent_id": "agent://acme.example/a"}},
		{Tags: map[string]string{"agent_id": "agent://acme.example/a"}}, // duplicate subject
		{Tags: map[string]string{"agent_id": "agent://acme.example/b"}},
		{Tags: map[string]string{"owner": "team-x"}}, // no agent_id: skipped
	}
	if err := e.EmitEvidenceSigned(findings, "ed25519", "sha256:deadbeef"); err != nil {
		t.Fatal(err)
	}
	got := readEvents(t, path)
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2 (one per distinct agent_id, not per finding)", len(got))
	}
	seen := map[string]bool{}
	for _, ev := range got {
		if ev.Type != TypeEvidenceSigned {
			t.Errorf("type = %q, want %q", ev.Type, TypeEvidenceSigned)
		}
		if ev.Data["alg"] != "ed25519" || ev.Data["fingerprint"] != "sha256:deadbeef" {
			t.Errorf("data = %v", ev.Data)
		}
		seen[ev.AgentID] = true
	}
	if !seen["agent://acme.example/a"] || !seen["agent://acme.example/b"] {
		t.Errorf("agent ids seen = %v, want both a and b", seen)
	}
}

// ------------------------------------------------------------------
// Fail-open on a bad path (Open itself), matching every other emitter in
// the stack (Wardryx's event.Writer, Verdryx's EventLog, Engram's).
// ------------------------------------------------------------------

func TestOpenFailsOnBadPath(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "nonexistent-dir", "events.ndjson")
	if _, err := Open(bad); err == nil {
		t.Fatal("Open: expected an error for a missing parent directory")
	}
}

func TestEmittedLinesAreValidNDJSON(t *testing.T) {
	e, path := mustOpen(t)
	findings := []model.Finding{
		{Tags: map[string]string{"agent_id": "agent://acme.example/a"}, Risk: model.Risk{Severity: model.SeverityHigh}},
		{Tags: map[string]string{"agent_id": "agent://acme.example/b"}, Risk: model.Risk{Severity: model.SeverityLow}},
	}
	if err := e.EmitFindings(findings); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	for i, line := range lines {
		if _, err := event.Unmarshal([]byte(line)); err != nil {
			t.Errorf("line %d not valid: %v (%q)", i, err, line)
		}
	}
}

// ------------------------------------------------------------------
// SPEC 6.5 prev_hash chain (agent-stack-go event.ChainedWriter). Proves the
// chain is actually wired through Exporter, not just present in
// agent-stack-go: three real events via EmitFindings, a reopen (simulating
// qryx running again against the same --events path) that must CONTINUE
// the chain rather than start a second head, and a final event.VerifyChain
// over the whole file.
// ------------------------------------------------------------------

func TestExportedEventsChainAcrossEmitsAndResume(t *testing.T) {
	e, path := mustOpen(t)
	if e.ResumedFrom() != "" {
		t.Fatalf("fresh file must start a fresh chain, got %q", e.ResumedFrom())
	}
	findings := []model.Finding{
		{Tags: map[string]string{"agent_id": "agent://acme.example/a"}, Risk: model.Risk{Severity: model.SeverityHigh}},
		{Tags: map[string]string{"agent_id": "agent://acme.example/b"}, Risk: model.Risk{Severity: model.SeverityLow}},
		{Tags: map[string]string{"agent_id": "agent://acme.example/c"}, Risk: model.Risk{Severity: model.SeverityMedium}},
	}
	if err := e.EmitFindings(findings); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	got := readEvents(t, path)
	if len(got) != 3 {
		t.Fatalf("events = %d, want 3", len(got))
	}
	if got[0].PrevHash != "" {
		t.Fatalf("head event must carry no prev_hash, got %q", got[0].PrevHash)
	}
	wantH1, err := event.ChainHash(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if got[1].PrevHash != wantH1 {
		t.Fatalf("event[1].PrevHash = %q, want %q (hash of event[0])", got[1].PrevHash, wantH1)
	}

	// Reopen against the same file: the chain must CONTINUE from the last
	// written event's hash (got[2]), not restart a second head.
	wantH2, err := event.ChainHash(got[2])
	if err != nil {
		t.Fatal(err)
	}
	e2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = e2.Close() })
	if e2.ResumedFrom() != wantH2 {
		t.Fatalf("resume: got %q want %q", e2.ResumedFrom(), wantH2)
	}
	if err := e2.EmitFindings([]model.Finding{
		{Tags: map[string]string{"agent_id": "agent://acme.example/d"}, Risk: model.Risk{Severity: model.SeverityInfo}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e2.Close(); err != nil {
		t.Fatalf("close 2: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	report, err := event.VerifyChain(f)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ok() {
		t.Fatalf("VerifyChain reported a break: %+v", report)
	}
	if len(report.HeadLines) != 1 {
		t.Fatalf("expected exactly 1 chain head (no restart across the reopen), got %+v", report.HeadLines)
	}
	if report.Chained != 3 {
		t.Fatalf("expected 3 chained events, got %+v", report)
	}
}
