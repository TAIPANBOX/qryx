package agentstack

import (
	"path/filepath"
	"testing"

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

// TestEventsMixedMalformedLinesTolerated exercises the "count, skip, never
// fatal" requirement: a stream with an unparseable line and a line with the
// wrong schema alongside one valid, chained event must still yield the
// chained-stream finding, not an error.
func TestEventsMixedMalformedLinesTolerated(t *testing.T) {
	got := mustScan(t, "testdata/events-mixed.ndjson")
	if len(got) != 1 {
		t.Fatalf("want 1 finding (malformed lines skipped, not fatal), got %d: %+v", len(got), got)
	}
	if got[0].Asset.Algorithm != "SHA-256" {
		t.Errorf("want the sha256 chain finding from the one valid event, got %+v", got[0].Asset)
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
		"passport-spiffe.json":      1,
		"passport-none.json":        1,
		"events-chained.ndjson":     1,
		"events-chained-v02.ndjson": 1,
		"events-nohash.ndjson":      1,
		"events-mixed.ndjson":       1,
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
