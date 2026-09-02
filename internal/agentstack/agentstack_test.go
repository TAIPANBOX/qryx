package agentstack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/qryx/internal/model"
)

func mustScan(t *testing.T, path string) []model.Finding {
	t.Helper()
	got, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestPassportSpiffeSVID(t *testing.T) {
	got := mustScan(t, "testdata/passport-spiffe.json")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Type != model.TypeCertificate || f.Asset.Algorithm != "X509" {
		t.Errorf("asset = %+v, want certificate/X509", f.Asset)
	}
	if f.Source != "agentstack" {
		t.Errorf("source = %q, want agentstack", f.Source)
	}
	if f.Risk.Class != "" {
		t.Errorf("risk class = %q, want empty (algorithm unknown, left for central classification)", f.Risk.Class)
	}
	if f.Tags["owner"] != "team-support@acme-bank.example" {
		t.Errorf("owner tag = %q", f.Tags["owner"])
	}
	if want := "agent://acme-bank.example/support/tier1-bot"; f.Tags["agent_id"] != want {
		t.Errorf("agent_id tag = %q, want %q", f.Tags["agent_id"], want)
	}
	if f.Location.File != "testdata/passport-spiffe.json" {
		t.Errorf("location = %q", f.Location.File)
	}
}

func TestPassportNoAttestation(t *testing.T) {
	got := mustScan(t, "testdata/passport-none.json")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Risk.Class != model.RiskMisconfig {
		t.Errorf("risk class = %q, want misconfig", f.Risk.Class)
	}
	if f.Risk.Severity != model.SeverityMedium {
		t.Errorf("risk severity = %v, want medium", f.Risk.Severity)
	}
	if f.Risk.Reason != "agent identity has no cryptographic attestation" {
		t.Errorf("reason = %q", f.Risk.Reason)
	}
	if f.Tags["owner"] != "team-platform@acme-bank.example" {
		t.Errorf("owner tag = %q", f.Tags["owner"])
	}
	if want := "agent://acme-bank.example/eng/ci-fixer/instance-7"; f.Tags["agent_id"] != want {
		t.Errorf("agent_id tag = %q, want %q", f.Tags["agent_id"], want)
	}
}

// TestPassportAttestationMethods table-tests every attestation.method value
// against passportFindings directly, covering mtls-cert/oidc/enclave-key/
// absent alongside the spiffe-svid and none fixtures already exercised above.
func TestPassportAttestationMethods(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		wantType model.AssetType
		wantAlgo string
		wantRisk model.RiskClass // "" means left for central classification
	}{
		{"mtls-cert", "mtls-cert", model.TypeCertificate, "X509", ""},
		{"spiffe-svid", "spiffe-svid", model.TypeCertificate, "X509", ""},
		{"enclave-key", "enclave-key", model.TypeKey, "enclave-key", model.RiskNone},
		{"oidc", "oidc", model.TypeProtocol, "OIDC", ""},
		{"none", "none", model.TypeProtocol, "no-attestation", model.RiskMisconfig},
		{"absent", "", model.TypeProtocol, "no-attestation", model.RiskMisconfig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := passport{ID: "agent://acme-bank.example/x", Owner: "team@acme-bank.example"}
			p.Attestation.Method = tc.method
			got := passportFindings("p.json", p)
			if len(got) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
			}
			f := got[0]
			if f.Asset.Type != tc.wantType || f.Asset.Algorithm != tc.wantAlgo {
				t.Errorf("asset = %+v, want %s/%s", f.Asset, tc.wantType, tc.wantAlgo)
			}
			if f.Risk.Class != tc.wantRisk {
				t.Errorf("risk class = %q, want %q", f.Risk.Class, tc.wantRisk)
			}
			if f.Tags["owner"] != "team@acme-bank.example" {
				t.Errorf("owner tag = %q", f.Tags["owner"])
			}
			if f.Tags["agent_id"] != "agent://acme-bank.example/x" {
				t.Errorf("agent_id tag = %q", f.Tags["agent_id"])
			}
		})
	}
}

func TestEventsChained(t *testing.T) {
	got := mustScan(t, "testdata/events-chained.ndjson")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Type != model.TypeAlgorithm || f.Asset.Algorithm != "SHA-256" {
		t.Errorf("asset = %+v, want algorithm/SHA-256", f.Asset)
	}
	if f.Risk.Class != "" {
		t.Errorf("risk class = %q, want empty (sha256 is fine; centrally classified)", f.Risk.Class)
	}
	// An event-stream finding is about the stream/file, not any one agent
	// within it -- it must carry no agent_id tag at all, never a fabricated
	// one, so package exporter correctly skips it (see exporter.agentIDFromTags).
	if _, ok := f.Tags["agent_id"]; ok {
		t.Errorf("event-stream finding must not carry an agent_id tag, got %q", f.Tags["agent_id"])
	}
}

// TestEventsSchemaV02Accepted proves the scanner accepts agent-event schema
// v0.2 (wardryx/verdryx/mockryx's schema, agent-passport SPEC.md §6.4:
// consumers MUST accept either v0.1 or v0.2) rather than treating a v0.2
// stream as unrecognized and silently dropping it. A v0.2 event line yields
// the same finding a v0.1 line with an equivalent hash chain would.
func TestEventsSchemaV02Accepted(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{"v0.1", "testdata/events-chained.ndjson"},
		{"v0.2", "testdata/events-chained-v02.ndjson"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mustScan(t, tc.file)
			if len(got) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
			}
			f := got[0]
			if f.Asset.Type != model.TypeAlgorithm || f.Asset.Algorithm != "SHA-256" {
				t.Errorf("asset = %+v, want algorithm/SHA-256", f.Asset)
			}
			if f.Risk.Class != "" {
				t.Errorf("risk class = %q, want empty (sha256 is fine; centrally classified)", f.Risk.Class)
			}
		})
	}
}

func TestEventsNoHashChain(t *testing.T) {
	got := mustScan(t, "testdata/events-nohash.ndjson")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Risk.Class != model.RiskMisconfig || f.Risk.Severity != model.SeverityLow {
		t.Errorf("risk = %+v, want misconfig/low", f.Risk)
	}
	if f.Risk.Reason != "agent event stream is not tamper-evident (no hash chain)" {
		t.Errorf("reason = %q", f.Risk.Reason)
	}
}

// TestEventsPartiallyChainedNotTamperEvident is the fail-before/pass-after
// case for the any-vs-all bug: a stream where only some events carry a
// prev_hash must NOT be reported tamper-evident. The old check ("chained >
// 0") called any stream with at least one chained event fully tamper-evident:
// a 1000-event stream with a single chained event passed the same as a
// fully chained one. This fixture has 3 events: event 1 carries a prev_hash,
// event 2 carries none, event 3 carries a prev_hash.
//
// What "not tamper-evident" means for this exact fixture changed with the
// head-aware pass 1 added alongside TestARealTokenFuseChainWithAHeadIsVerified.
// Event 2's missing prev_hash is no longer read as a gap: per SPEC.md §6.5, an
// event with no prev_hash is a legitimate head, and a head anywhere but line
// one is a legal restart, so pass 1 now treats event 2 as the second of two
// heads and lets the stream through to cryptographic verification. It is pass
// 2 (event.VerifyChain) that catches this fixture now: event 3's stored
// prev_hash was hand-typed to look plausible and does not actually equal the
// real hash of event 2, so it comes back a genuine break, not a structural
// gap. The regression this test protects against -- a stream that is not
// genuinely, fully chained must never be reported verified -- still holds;
// it is now caught one layer deeper, by recomputation instead of shape.
func TestEventsPartiallyChainedNotTamperEvident(t *testing.T) {
	got := mustScan(t, "testdata/events-partially-chained.ndjson")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Risk.Class != model.RiskMisconfig {
		t.Errorf("risk class = %q, want %q (a stream that does not genuinely chain is not tamper-evident)", f.Risk.Class, model.RiskMisconfig)
	}
	if f.Asset.Algorithm == "SHA-256" {
		t.Error("this stream must not report the tamper-evident SHA-256 asset")
	}
	if f.Asset.Algorithm != "hash-chain-broken" {
		t.Errorf("algorithm = %q, want %q: event 2's missing prev_hash is now a legal restart, so this is caught by cryptographic verification finding event 3's hash does not check out, not by the structural pass", f.Asset.Algorithm, "hash-chain-broken")
	}
	if !strings.Contains(f.Evidence, "line 3") {
		t.Errorf("evidence must name the broken line (3): %q", f.Evidence)
	}
}

// TestEventsDuplicateHashNotTamperEvident covers the other failure mode named
// in the bug report: every event carries a prev_hash (chained == len(events)
// passes the any-vs-all fix on its own), but it is the exact same fixed value
// on every line, not a real per-event chain, just a dummy placeholder. A
// genuine chain links each event to a different predecessor, so the same
// hash value repeating is a structural tell that this isn't a real chain,
// even without recomputing the actual hash.
func TestEventsDuplicateHashNotTamperEvident(t *testing.T) {
	got := mustScan(t, "testdata/events-dummy-chain.ndjson")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Risk.Class != model.RiskMisconfig {
		t.Errorf("risk class = %q, want %q (a repeated/dummy prev_hash is not a real chain)", f.Risk.Class, model.RiskMisconfig)
	}
}

// TestEventsChainedFabricatedHashesNotVerified is the regression test for the
// defect this change fixes: eventStreamFindings used to judge a stream
// tamper-evident purely structurally (every event carries a well-formed,
// mutually distinct sha256 prev_hash), never recomputing the RFC 8785 (JCS)
// canonical hash SPEC.md 6.5 actually defines prev_hash to be. This fixture's
// three events each carry a well-formed, mutually distinct prev_hash
// (0xa1..., 0xb2..., 0xc3... repeated to 64 hex chars) that structurally
// looks exactly like a real chain and is NOT: none of them is the actual
// hash of the event before it. A stream like this must be reported broken,
// never verified.
func TestEventsChainedFabricatedHashesNotVerified(t *testing.T) {
	got := mustScan(t, "testdata/events-chained-fabricated.ndjson")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Algorithm == "SHA-256" && f.Risk.Class == "" {
		t.Fatalf("fabricated-but-well-formed hashes must not be reported verified: %+v", f)
	}
	if f.Risk.Class != model.RiskMisconfig {
		t.Errorf("risk class = %q, want %q (a cryptographically broken chain is a misconfig, same vocabulary as a missing one)", f.Risk.Class, model.RiskMisconfig)
	}
	if f.Risk.Severity < model.SeverityLow {
		t.Errorf("risk severity = %v, want at least %v (what a missing chain gets today)", f.Risk.Severity, model.SeverityLow)
	}
	if !strings.Contains(f.Risk.Reason, "cryptograph") && !strings.Contains(f.Evidence, "cryptograph") {
		t.Errorf("reason/evidence must say the chain was checked cryptographically: reason=%q evidence=%q", f.Risk.Reason, f.Evidence)
	}
	if !strings.Contains(f.Evidence, "line 2") {
		t.Errorf("evidence must name the first broken line (2): %q", f.Evidence)
	}
}

// TestEventsGenuinelyChainedVerified is the positive twin of
// TestEventsChainedFabricatedHashesNotVerified: a stream built with
// event.ChainHash itself, so its hashes are provably real rather than merely
// well-formed and distinct, is reported verified once cryptographic
// verification runs.
//
// The file written here is the SECOND and THIRD of three real, chained
// events; the true head (empty prev_hash) is computed but deliberately never
// written, mirroring how a rotated log segment opens mid-chain (SPEC.md
// §6.5 legally allows this). That is also the only way to reach the
// cryptographic check at all: the cheap structural pass this function still
// runs first requires every event in the file, including the first, to
// carry a well-formed prev_hash (see TestEventsPartiallyChainedNotTamperEvident),
// so a stream that genuinely opens with an empty-prev_hash head never gets
// past pass 1 -- a pre-existing property of the cheap pass, unchanged here.
func TestEventsGenuinelyChainedVerified(t *testing.T) {
	head := event.Event{
		Schema: event.SchemaV02, TS: "2026-08-10T09:00:00Z", Source: "wardryx",
		Type: "policy_violation", AgentID: "agent://acme-bank.example/support/tier1-bot",
		Severity: "high", Data: map[string]any{"rule": "no-plaintext-secrets"},
	}
	headHash, err := event.ChainHash(head)
	if err != nil {
		t.Fatalf("ChainHash(head): %v", err)
	}

	mid := event.Event{
		Schema: event.SchemaV02, TS: "2026-08-10T09:01:00Z", Source: "verdryx",
		Type: "verification_failed", AgentID: "agent://acme-bank.example/support/tier1-bot",
		Severity: "medium", Data: map[string]any{"check": "output-provenance"},
		PrevHash: headHash,
	}
	midHash, err := event.ChainHash(mid)
	if err != nil {
		t.Fatalf("ChainHash(mid): %v", err)
	}

	tail := event.Event{
		Schema: event.SchemaV02, TS: "2026-08-10T09:02:00Z", Source: "engram",
		Type: "memory_written", AgentID: "agent://acme-bank.example/support/tier1-bot",
		Severity: "info", Data: map[string]any{"memory_id": "mem-9"},
		PrevHash: midHash,
	}

	path := filepath.Join(t.TempDir(), "events-real-chain.ndjson")
	writeEvents(t, path, mid, tail)

	got := mustScan(t, path)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Type != model.TypeAlgorithm || f.Asset.Algorithm != "SHA-256" {
		t.Errorf("asset = %+v, want algorithm/SHA-256 (genuinely verified)", f.Asset)
	}
	if f.Risk.Class != "" {
		t.Errorf("risk class = %q, want empty: a genuinely chained stream is not a finding to flag", f.Risk.Class)
	}
	if !strings.Contains(f.Evidence, "cryptographically verified") {
		t.Errorf("evidence should say the chain was cryptographically verified: %q", f.Evidence)
	}
}

// TestARealTokenFuseChainWithAHeadIsVerified is the regression test for the
// gap TestEventsGenuinelyChainedVerified's "drop the head" construction left
// open: a stream that genuinely, properly opens with an empty-prev_hash head
// at line one -- the ordinary shape any real producer following
// agent-passport SPEC.md §6.5 writes, and the one shape neither
// TestEventsChained nor TestEventsGenuinelyChainedVerified could exercise,
// because both were built (or, for the pre-existing fixture, patched) to
// satisfy the OLD pass 1, which required every event including the first to
// carry a prev_hash.
//
// testdata/events-tokenfuse-real.ndjson is not synthetic: it is a byte-for-
// byte copy of a real agent-event stream written by a real container,
// ghcr.io/taipanbox/tokenfuse:v0.4.1, run with TOKENFUSE_EVENTS_PATH set,
// stopped with SIGINT to flush. Three API calls against a 1-microdollar
// budget each tripped the breaker, so the gateway wrote three
// breaker_tripped events; the fourth call in the same run (a real budget)
// did not trip the breaker and is absent, which is why this file has three
// lines, not four. Line 1 carries no prev_hash at all (the expected head);
// its independently-recomputed event.ChainHash matches line 2's prev_hash
// exactly, and line 2's matches line 3's, confirmed by hand before writing
// this test. Before this change, pass 1 rejected this genuinely correct
// file as "only partially hash-chained" and never reached cryptographic
// verification at all -- a check red on a correct build, the worst shape a
// check can take.
func TestARealTokenFuseChainWithAHeadIsVerified(t *testing.T) {
	got := mustScan(t, "testdata/events-tokenfuse-real.ndjson")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Type != model.TypeAlgorithm || f.Asset.Algorithm != "SHA-256" {
		t.Errorf("asset = %+v, want algorithm/SHA-256 (genuinely verified)", f.Asset)
	}
	if f.Risk.Class != "" {
		t.Errorf("risk class = %q, want empty: a real chain with a proper head is not a finding to flag", f.Risk.Class)
	}
	if !strings.Contains(f.Evidence, "cryptographically verified") {
		t.Errorf("evidence should say the chain was cryptographically verified: %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "1 head") {
		t.Errorf("evidence should say how many heads it saw (1: one continuous chain): %q", f.Evidence)
	}
}

// writeEvents marshals each event as one NDJSON line and writes them to path.
func writeEvents(t *testing.T, path string, events ...event.Event) {
	t.Helper()
	var buf []byte
	for _, e := range events {
		line, err := event.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestEventStreamHostileInputs covers the inputs a real product's event
// stream could plausibly contain that are not simply "well-formed" or
// "malformed" in the ways the tests above already exercise: each case here
// must yield a finding or a clean refusal (a file this package does not
// recognize, or nothing to say), and must never panic.
func TestEventStreamHostileInputs(t *testing.T) {
	agentID := "agent://acme-bank.example/support/tier1-bot"

	t.Run("malformed_json_line_in_the_middle", func(t *testing.T) {
		e1 := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:00:00Z", Source: "tokenfuse", Type: "budget_exhausted", AgentID: agentID, Data: map[string]any{"n": 1}, PrevHash: "sha256:" + strings.Repeat("d4", 32)}
		e3 := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:02:00Z", Source: "engram", Type: "memory_written", AgentID: agentID, Data: map[string]any{"n": 3}, PrevHash: "sha256:" + strings.Repeat("e5", 32)}
		l1, err := event.Marshal(e1)
		if err != nil {
			t.Fatalf("marshal e1: %v", err)
		}
		l3, err := event.Marshal(e3)
		if err != nil {
			t.Fatalf("marshal e3: %v", err)
		}
		content := string(l1) + "\n" + "{this is not valid json" + "\n" + string(l3) + "\n"
		path := filepath.Join(t.TempDir(), "malformed-middle.ndjson")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		got := mustScan(t, path)
		if len(got) != 1 {
			t.Fatalf("want 1 finding (never a panic, never fatal), got %d: %+v", len(got), got)
		}
		if got[0].Risk.Class != model.RiskMisconfig {
			t.Errorf("risk class = %q, want %q: a malformed line in the middle must not let the stream read as verified", got[0].Risk.Class, model.RiskMisconfig)
		}
	})

	t.Run("empty_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.ndjson")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := Scan(path)
		if err != nil {
			t.Fatalf("an empty file must be a clean refusal, not an error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("want 0 findings for an empty file, got %d: %+v", len(got), got)
		}
	})

	t.Run("line_over_1MiB_is_a_clean_refusal_upstream", func(t *testing.T) {
		// A single line past parseEvents' own 1 MiB scanner buffer (matching
		// Scan's documented tolerance) makes the file unrecognizable as an
		// event stream before eventStreamFindings is ever reached: no
		// events are extracted, so scanFile logs and skips it, same as any
		// other file it cannot classify. This is upstream of this change and
		// documents the boundary the next case tests on the other side of.
		e := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:00:00Z", Source: "engram", Type: "memory_written", AgentID: agentID, Data: map[string]any{"pad": strings.Repeat("x", 1_200_000)}}
		line, err := event.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if len(line) <= 1<<20 {
			t.Fatalf("fixture line is only %d bytes, want > 1 MiB", len(line))
		}
		path := filepath.Join(t.TempDir(), "giant-line.ndjson")
		if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		got, err := Scan(path)
		if err != nil {
			t.Fatalf("never a panic, never fatal: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("want 0 findings (unrecognized, logged and skipped), got %d: %+v", len(got), got)
		}
	})

	t.Run("line_over_1MiB_reaches_verify_chain", func(t *testing.T) {
		// agent-stack-go's own VerifyChain scans with a 4 MiB buffer, larger
		// than parseEvents' 1 MiB, so a line this package's OWN loose parser
		// could never have produced can still legitimately reach
		// eventStreamFindings once the structural pass has already been
		// satisfied by some other means -- exactly what a caller bypassing
		// parseEvents' limit (a future larger buffer, a different producer)
		// would look like. This calls eventStreamFindings directly with a
		// hand-built events slice standing in for what an uncapped parse
		// would have extracted, and a raw content buffer that genuinely
		// contains the oversized line, to prove the cryptographic path
		// itself does not choke on it.
		giant := event.Event{
			Schema: event.SchemaV02, TS: "2026-08-10T09:00:00Z", Source: "engram", Type: "memory_written",
			AgentID: agentID, Data: map[string]any{"pad": strings.Repeat("x", 1_200_000)},
			PrevHash: "sha256:" + strings.Repeat("d4", 32), // placeholder: always unverifiable as line 1, value irrelevant
		}
		giantLine, err := event.Marshal(giant)
		if err != nil {
			t.Fatalf("marshal giant: %v", err)
		}
		if n := len(giantLine); n <= 1<<20 || n >= 4<<20 {
			t.Fatalf("fixture line is %d bytes, want strictly between 1 MiB and 4 MiB", n)
		}
		giantHash, err := event.ChainHash(giant)
		if err != nil {
			t.Fatalf("ChainHash(giant): %v", err)
		}
		second := event.Event{
			Schema: event.SchemaV02, TS: "2026-08-10T09:01:00Z", Source: "tokenfuse", Type: "spend_spike",
			AgentID: agentID, Data: map[string]any{"budget_usd": 1.0}, PrevHash: giantHash,
		}
		secondLine, err := event.Marshal(second)
		if err != nil {
			t.Fatalf("marshal second: %v", err)
		}
		content := append(append(giantLine, '\n'), append(secondLine, '\n')...)

		events := []agentEvent{
			{Schema: giant.Schema, AgentID: giant.AgentID, PrevHash: giant.PrevHash},
			{Schema: second.Schema, AgentID: second.AgentID, PrevHash: second.PrevHash},
		}

		got := eventStreamFindings("giant.ndjson", events, content)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
		}
		if got[0].Asset.Algorithm != "SHA-256" || got[0].Risk.Class != "" {
			t.Errorf("a genuinely chained stream with one oversized-but-real event should still verify, got %+v", got[0])
		}
	})

	t.Run("line_over_4MiB_verify_chain_itself_cannot_scan_it", func(t *testing.T) {
		// event.VerifyChain scans with its own 4 MiB buffer and, unlike
		// parseEvents, surfaces a scan failure as a returned error rather
		// than silently truncating. A line past even that must still
		// produce a finding, not a panic, and must say verification did
		// not complete rather than claim anything about the chain.
		massive := event.Event{
			Schema: event.SchemaV02, TS: "2026-08-10T09:00:00Z", Source: "engram", Type: "memory_written",
			AgentID: agentID, Data: map[string]any{"pad": strings.Repeat("x", 4_300_000)},
			PrevHash: "sha256:" + strings.Repeat("d4", 32),
		}
		massiveLine, err := event.Marshal(massive)
		if err != nil {
			t.Fatalf("marshal massive: %v", err)
		}
		if len(massiveLine) <= 4<<20 {
			t.Fatalf("fixture line is only %d bytes, want > 4 MiB", len(massiveLine))
		}
		content := append(massiveLine, '\n')
		events := []agentEvent{{Schema: massive.Schema, AgentID: massive.AgentID, PrevHash: massive.PrevHash}}

		got := eventStreamFindings("massive.ndjson", events, content)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
		}
		f := got[0]
		if f.Risk.Class != model.RiskMisconfig {
			t.Errorf("risk class = %q, want %q", f.Risk.Class, model.RiskMisconfig)
		}
		if !strings.Contains(f.Evidence, "could not be checked") {
			t.Errorf("evidence must say verification did not complete, not claim a verdict: %q", f.Evidence)
		}
	})

	t.Run("prev_hash_right_prefix_wrong_length", func(t *testing.T) {
		e1 := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:00:00Z", Source: "tokenfuse", Type: "budget_exhausted", AgentID: agentID, Data: map[string]any{"n": 1}, PrevHash: "sha256:" + strings.Repeat("d4", 32)}
		// Right prefix, nowhere near the required 64 hex chars.
		e2 := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:01:00Z", Source: "engram", Type: "memory_written", AgentID: agentID, Data: map[string]any{"n": 2}, PrevHash: "sha256:deadbeef"}
		path := filepath.Join(t.TempDir(), "wrong-length.ndjson")
		writeEvents(t, path, e1, e2)

		got := mustScan(t, path)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
		}
		f := got[0]
		if f.Risk.Class != model.RiskMisconfig {
			t.Errorf("risk class = %q, want %q: a wrong-length hash cannot match a real 64-hex-char digest", f.Risk.Class, model.RiskMisconfig)
		}
		if !strings.Contains(f.Evidence, "line 2") {
			t.Errorf("evidence must name the broken line (2): %q", f.Evidence)
		}
	})

	t.Run("first_event_carries_a_prev_hash", func(t *testing.T) {
		// There is no previous event in this file at all -- SPEC.md §6.5
		// treats this as a legal chain restart (a rotated segment), not
		// tampering, so VerifyChain must not report it broken.
		lone := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:00:00Z", Source: "tokenfuse", Type: "budget_exhausted", AgentID: agentID, Data: map[string]any{"n": 1}, PrevHash: "sha256:" + strings.Repeat("d4", 32)}
		path := filepath.Join(t.TempDir(), "stray-head.ndjson")
		writeEvents(t, path, lone)

		got := mustScan(t, path)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
		}
		if got[0].Risk.Class != "" || got[0].Asset.Algorithm != "SHA-256" {
			t.Errorf("a lone stray prev_hash with nothing to contradict it must not be reported broken, got %+v", got[0])
		}
	})

	t.Run("non_head_prev_hash_not_sha256_shaped", func(t *testing.T) {
		// A genuinely NEW structural category the head-aware pass 1
		// introduces: an event that is not a head (its prev_hash field is
		// present, so SPEC.md §6.5 does not exempt it) but whose value is
		// not even sha256:-shaped. Before this field existed as a thing to
		// check, this line was indistinguishable from any other
		// "not chained" event; now it is its own reason, caught structurally,
		// never reaching the expensive cryptographic pass.
		head := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:00:00Z", Source: "tokenfuse", Type: "budget_exhausted", AgentID: agentID, Data: map[string]any{"n": 1}}
		bogus := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:01:00Z", Source: "engram", Type: "memory_written", AgentID: agentID, Data: map[string]any{"n": 2}, PrevHash: "not-a-real-hash-at-all"}
		path := filepath.Join(t.TempDir(), "malformed-shape.ndjson")
		writeEvents(t, path, head, bogus)

		got := mustScan(t, path)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
		}
		f := got[0]
		if f.Asset.Algorithm != "no-hash-chain" {
			t.Errorf("algorithm = %q, want %q: a malformed-shape prev_hash on a non-head event is a structural rejection, never reaching event.VerifyChain", f.Asset.Algorithm, "no-hash-chain")
		}
		if f.Risk.Class != model.RiskMisconfig {
			t.Errorf("risk class = %q, want %q", f.Risk.Class, model.RiskMisconfig)
		}
		if !strings.Contains(f.Evidence, "not sha256:-shaped") {
			t.Errorf("evidence must name the specific problem (not sha256:-shaped): %q", f.Evidence)
		}
	})

	t.Run("restart_mid_file_is_verified_with_two_heads_reported", func(t *testing.T) {
		// Two genuinely chained two-event segments concatenated in one file
		// (segment 1: head -> link; segment 2: another head -> link), the
		// shape a rotated log or a process that restarted mid-stream
		// produces. SPEC.md §6.5 makes the second head a legal restart, not
		// a break, so this must verify -- and because "verified" alone would
		// wrongly read as "one continuous 4-event history," the evidence
		// must say 2 heads, so a reader can tell it is two chains.
		head1 := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:00:00Z", Source: "tokenfuse", Type: "budget_exhausted", AgentID: agentID, Data: map[string]any{"n": 1}}
		hash1, err := event.ChainHash(head1)
		if err != nil {
			t.Fatalf("ChainHash(head1): %v", err)
		}
		link1 := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:01:00Z", Source: "engram", Type: "memory_written", AgentID: agentID, Data: map[string]any{"n": 2}, PrevHash: hash1}

		head2 := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:02:00Z", Source: "wardryx", Type: "policy_violation", AgentID: agentID, Data: map[string]any{"n": 3}}
		hash2, err := event.ChainHash(head2)
		if err != nil {
			t.Fatalf("ChainHash(head2): %v", err)
		}
		link2 := event.Event{Schema: event.SchemaV02, TS: "2026-08-10T09:03:00Z", Source: "verdryx", Type: "verification_failed", AgentID: agentID, Data: map[string]any{"n": 4}, PrevHash: hash2}

		path := filepath.Join(t.TempDir(), "two-segments.ndjson")
		writeEvents(t, path, head1, link1, head2, link2)

		got := mustScan(t, path)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
		}
		f := got[0]
		if f.Asset.Algorithm != "SHA-256" || f.Risk.Class != "" {
			t.Errorf("two internally-consistent chained segments must verify, not break, got %+v", f)
		}
		if !strings.Contains(f.Evidence, "2 heads") {
			t.Errorf("evidence must say 2 heads (two separate chains), not imply one continuous history: %q", f.Evidence)
		}
	})
}

// TestEventsMixedMalformedLinesTolerated exercises the "count, skip, never
// fatal" requirement: a stream with an unparseable line and a line with the
// wrong schema alongside one valid, chained-looking event must still yield
// one finding, not an error or a panic. It must NOT be the verified/SHA-256
// finding, though: cryptographic verification (event.VerifyChain) sees the
// same two bad lines in the raw stream, and the one recognized event's
// prev_hash cannot actually be checked against anything, since nothing
// legitimate precedes it -- that is the "malformed lines poisoned
// verification" outcome, correctly less confident than the old structural-
// only check, which had no way to notice the difference.
func TestEventsMixedMalformedLinesTolerated(t *testing.T) {
	got := mustScan(t, "testdata/events-mixed.ndjson")
	if len(got) != 1 {
		t.Fatalf("want 1 finding (malformed lines skipped, not fatal), got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Algorithm == "SHA-256" {
		t.Errorf("a lone event preceded by malformed lines must not be reported verified, got %+v", f.Asset)
	}
	if f.Risk.Class != model.RiskMisconfig {
		t.Errorf("risk class = %q, want %q", f.Risk.Class, model.RiskMisconfig)
	}
	if !strings.Contains(f.Evidence, "malformed") {
		t.Errorf("evidence must say malformed lines are why verification is incomplete: %q", f.Evidence)
	}
}

func TestUnrecognizedFileSkippedNotFatal(t *testing.T) {
	got, err := Scan("testdata/malformed.json")
	if err != nil {
		t.Fatalf("an unrecognized file must not be a fatal error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want 0 findings for an unrecognized file, got %d", len(got))
	}
}

// TestScanDirectory is the connector-entrypoint test mirroring how the CLI
// invokes this package (qryx agents <dir>): a directory mixing passports,
// event streams, and one malformed file must still yield exactly the
// findings the recognized files produce.
func TestScanDirectory(t *testing.T) {
	got := mustScan(t, "testdata")

	byFile := map[string]int{}
	for _, f := range got {
		byFile[filepath.Base(f.Location.File)]++
	}

	want := map[string]int{
		"passport-spiffe.json":             1,
		"passport-none.json":               1,
		"events-chained.ndjson":            1,
		"events-chained-v02.ndjson":        1,
		"events-nohash.ndjson":             1,
		"events-mixed.ndjson":              1,
		"events-partially-chained.ndjson":  1,
		"events-dummy-chain.ndjson":        1,
		"events-chained-fabricated.ndjson": 1,
		"events-tokenfuse-real.ndjson":     1,
	}
	for file, n := range want {
		if byFile[file] != n {
			t.Errorf("%s: got %d finding(s), want %d", file, byFile[file], n)
		}
	}
	if byFile["malformed.json"] != 0 {
		t.Errorf("malformed.json should produce no findings, got %d", byFile["malformed.json"])
	}
	if len(got) != len(want) {
		t.Errorf("total findings = %d, want %d", len(got), len(want))
	}
}
