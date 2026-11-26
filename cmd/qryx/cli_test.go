package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/store"
)

// runCLI runs the command line with its output captured in buffers, so a test
// can read everything a run printed, whatever its size.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	err = runWith(args, &out, &errb)
	return out.String(), errb.String(), err
}

// wantExit asserts that a run ended with exactly the given exit status.
func wantExit(t *testing.T, err error, code int) {
	t.Helper()
	var ec exitCode
	if !errors.As(err, &ec) {
		t.Fatalf("got %v, want exit status %d", err, code)
	}
	if int(ec) != code {
		t.Fatalf("got exit status %d, want %d", int(ec), code)
	}
}

const (
	sampleTree = "../../testdata/sample"
	policyFile = "../../testdata/policy.json"
	agentsData = "../../internal/agentstack/testdata"
)

// writeTree creates a directory holding the given files and returns its path.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// md5Only is a tree whose only finding is MD5: weak, severity high, never
// critical. It sits exactly on the boundary the severity gates compare against.
const md5Source = `package x

import "crypto/md5"

func h() { _ = md5.New() }
`

const sha1Source = `package x

import "crypto/sha1"

func h() { _ = sha1.New() }
`

// writeSigningKey writes a fresh PKCS#8 ed25519 key and returns its path.
func writeSigningKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "sign.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The command's output must reach the writers it is handed, not the process's
// own stdout: that is what lets a caller (and this suite) read a whole report.
func TestRunWritesToTheWritersItIsGiven(t *testing.T) {
	out, _, err := runCLI(t, "scan", "--include-tests", sampleTree)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(out, "MD5") {
		t.Errorf("stdout carries no report of the sample tree: %q", out)
	}
	_, errOut, err := runCLI(t)
	if err == nil {
		t.Fatal("no command must be an error")
	}
	if !strings.Contains(errOut, "usage:") {
		t.Errorf("usage did not reach the stderr writer: %q", errOut)
	}
}

// Every way of calling a subcommand without what it needs is refused with an
// error that names the missing piece, and prints the usage, rather than
// scanning something the operator did not ask for.
func TestEveryCommandRefusesMissingArguments(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"frobnicate"}, `unknown command "frobnicate"`},
		{[]string{"scan"}, "scan requires exactly one path"},
		{[]string{"scan", "a", "b"}, "scan requires exactly one path"},
		{[]string{"fix"}, "fix requires exactly one path"},
		{[]string{"trend"}, "trend requires exactly one evidence-trail file"},
		{[]string{"verify-evidence"}, "verify-evidence requires exactly one evidence file"},
		{[]string{"tls"}, "tls requires at least one host:port target"},
		{[]string{"ssh"}, "ssh requires at least one host:port target"},
		{[]string{"bin"}, "bin requires at least one file or directory"},
		{[]string{"image"}, "image requires at least one image tarball"},
		{[]string{"gcp"}, "gcp requires --project"},
		{[]string{"azure"}, "azure requires --vault-url"},
		{[]string{"agents"}, "agents requires exactly one path"},
		{[]string{"scan", "--no-such-flag", "."}, "no-such-flag"},
	} {
		_, errOut, err := runCLI(t, tc.args...)
		if err == nil {
			t.Errorf("%v: returned nil, want %q", tc.args, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: error %q does not say %q", tc.args, err, tc.want)
		}
		if !strings.Contains(errOut, "usage:") {
			t.Errorf("%v: no usage printed", tc.args)
		}
	}
}

// Each --format value selects its own writer. A swapped case would hand a CI
// job expecting a CBOM an HTML page, so each output is checked for the marker
// only its own writer produces.
func TestEachFormatSelectsItsOwnWriter(t *testing.T) {
	for format, marker := range map[string]string{
		"human":        "sources scanned",
		"cbom":         `"bomFormat": "CycloneDX"`,
		"html":         "<title>qryx: cryptography report</title>",
		"cnsa":         `"standard": "CNSA 2.0"`,
		"cnsa-html":    "<title>qryx: CNSA 2.0 Audit Report</title>",
		"migration":    `"toMigrate"`,
		"evidence":     `"scorePct"`,
		"ai-inventory": `"schema": "qryx.ai-inventory/v1"`,
		"dashboard":    "<title>qryx: Governance Dashboard</title>",
		"ncsc":         `"standard": "NCSC PQC migration timeline`,
		"ncsc-html":    "<title>qryx: NCSC PQC Migration Readiness Report</title>",
	} {
		out, _, err := runCLI(t, "scan", "--format", format, sampleTree)
		if err != nil {
			t.Errorf("--format %s: %v", format, err)
			continue
		}
		if !strings.Contains(out, marker) {
			t.Errorf("--format %s: output does not carry %q", format, marker)
		}
	}
	if _, _, err := runCLI(t, "scan", "--format", "yaml", sampleTree); err == nil || !strings.Contains(err.Error(), `unknown format "yaml"`) {
		t.Errorf("an unknown format must be refused, got %v", err)
	}
}

// --fail-on fires at or above its threshold and not below it. The MD5-only
// tree is high, so critical passes and high fails: an off-by-one in the
// comparison flips one of the two.
func TestFailOnGatesAtTheThresholdAndNotBelow(t *testing.T) {
	tree := writeTree(t, map[string]string{"h.go": md5Source})

	_, _, err := runCLI(t, "scan", "--fail-on", "high", tree)
	wantExit(t, err, 2)

	if _, _, err := runCLI(t, "scan", "--fail-on", "critical", tree); err != nil {
		t.Errorf("--fail-on critical on a high-only tree: got %v, want a pass", err)
	}
	if _, _, err := runCLI(t, "scan", "--fail-on", "severe", tree); err == nil || !strings.Contains(err.Error(), `invalid --fail-on value "severe"`) {
		t.Errorf("an unknown severity must be refused, got %v", err)
	}
	// A tree with nothing in it passes even the lowest gate.
	if _, _, err := runCLI(t, "scan", "--fail-on", "low", t.TempDir()); err != nil {
		t.Errorf("--fail-on low on an empty tree: got %v, want a pass", err)
	}
}

// --fail-on-new reads only what is new against the baseline: the same tree
// against its own snapshot passes, the same tree against an empty snapshot
// fails, and the threshold boundary holds here too.
func TestFailOnNewGatesOnlyNewAssets(t *testing.T) {
	tree := writeTree(t, map[string]string{"h.go": md5Source})
	dir := t.TempDir()
	same := filepath.Join(dir, "same.json")
	empty := filepath.Join(dir, "empty.json")

	if _, _, err := runCLI(t, "scan", "--save", same, tree); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "scan", "--save", empty, t.TempDir()); err != nil {
		t.Fatal(err)
	}

	if _, _, err := runCLI(t, "scan", "--baseline", same, "--fail-on-new", "low", tree); err != nil {
		t.Errorf("nothing is new against its own snapshot, got %v", err)
	}
	_, _, err := runCLI(t, "scan", "--baseline", empty, "--fail-on-new", "high", tree)
	wantExit(t, err, 2)
	if _, _, err := runCLI(t, "scan", "--baseline", empty, "--fail-on-new", "critical", tree); err != nil {
		t.Errorf("a new high asset must not trip --fail-on-new critical, got %v", err)
	}
	if _, _, err := runCLI(t, "scan", "--baseline", empty, "--fail-on-new", "bogus", tree); err == nil || !strings.Contains(err.Error(), `invalid --fail-on-new value "bogus"`) {
		t.Errorf("an unknown severity must be refused, got %v", err)
	}

	// The human report shows the drift it computed.
	out, _, err := runCLI(t, "scan", "--baseline", empty, tree)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "MD5") || !strings.Contains(strings.ToLower(out), "drift") {
		t.Errorf("human output against a baseline does not report the drift: %q", out)
	}
}

// A baseline that exists but cannot be read is an error, never "no baseline":
// treating it as missing would let the drift gates fall back to a pass.
func TestACorruptBaselineIsAnError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "scan", "--baseline", bad, sampleTree)
	if err == nil || !strings.Contains(err.Error(), "load baseline") {
		t.Fatalf("got %v, want a load baseline error", err)
	}
}

// A --save that cannot be written is an error, not a silently missing snapshot.
func TestAnUnwritableSnapshotIsAnError(t *testing.T) {
	target := filepath.Join(t.TempDir(), "no-such-dir", "snap.json")
	_, _, err := runCLI(t, "scan", "--save", target, sampleTree)
	if err == nil || !strings.Contains(err.Error(), "save snapshot") {
		t.Fatalf("got %v, want a save snapshot error", err)
	}
}

// --policy exits 3 on a violation and names the policy on stderr; a tree with
// nothing forbidden passes; with --policy-new-only only new violations count.
func TestPolicyGate(t *testing.T) {
	_, errOut, err := runCLI(t, "scan", "--policy", policyFile, sampleTree)
	wantExit(t, err, 3)
	if !strings.Contains(errOut, "example-strict") {
		t.Errorf("violations are not attributed to the policy by name: %q", errOut)
	}

	clean := writeTree(t, map[string]string{"README": "no cryptography here\n"})
	if _, _, err := runCLI(t, "scan", "--policy", policyFile, clean); err != nil {
		t.Errorf("a tree with nothing forbidden: got %v, want a pass", err)
	}

	base := filepath.Join(t.TempDir(), "base.json")
	if _, _, err := runCLI(t, "scan", "--save", base, sampleTree); err != nil {
		t.Fatal(err)
	}
	_, errOut, err = runCLI(t, "scan", "--policy", policyFile, "--baseline", base, "--policy-new-only", sampleTree)
	if err != nil {
		t.Errorf("violations already in the baseline are not new, got %v", err)
	}
	if !strings.Contains(errOut, "(new vs baseline)") {
		t.Errorf("the report does not say it gated only new assets: %q", errOut)
	}

	if _, _, err := runCLI(t, "scan", "--policy", policyFile, "--policy-new-only", sampleTree); err == nil || !strings.Contains(err.Error(), "--policy-new-only requires --baseline") {
		t.Errorf("--policy-new-only without --baseline must be refused, got %v", err)
	}
	if _, _, err := runCLI(t, "scan", "--policy", filepath.Join(t.TempDir(), "missing.json"), sampleTree); err == nil {
		t.Error("a policy that cannot be loaded must be an error")
	}
}

// --save-evidence appends the run's verdict to the trail, and trend reads it
// back.
func TestSaveEvidenceThenTrend(t *testing.T) {
	trail := filepath.Join(t.TempDir(), "trail.jsonl")
	if _, _, err := runCLI(t, "scan", "--save-evidence", trail, sampleTree); err != nil {
		t.Fatal(err)
	}
	recs, err := store.JSONLTrail{Path: trail}.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Root != sampleTree || recs[0].Total != 8 || recs[0].Digest == "" {
		t.Fatalf("trail holds %+v, want one record of the 8-asset sample with a digest", recs)
	}

	out, _, err := runCLI(t, "trend", trail)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1 record(s)") || !strings.Contains(out, recs[0].Digest[:len("sha256:")+12]) {
		t.Errorf("trend does not show the recorded run: %q", out)
	}
	out, _, err = runCLI(t, "trend", "--html", trail)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<html") {
		t.Errorf("trend --html did not render a page: %q", out)
	}

	bad := filepath.Join(t.TempDir(), "no-such-dir", "trail.jsonl")
	if _, _, err := runCLI(t, "scan", "--save-evidence", bad, sampleTree); err == nil || !strings.Contains(err.Error(), "save evidence") {
		t.Errorf("an unwritable trail must be an error, got %v", err)
	}
}

// trend --fail-on-regression exits 3 when the latest score is below the one
// before it, and only then: an equal or rising score passes.
func TestTrendFailsOnlyOnARegression(t *testing.T) {
	trailOf := func(scores ...int) string {
		p := filepath.Join(t.TempDir(), "trail.jsonl")
		for i, s := range scores {
			rec := store.EvidenceRecord{CreatedAt: time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC), Root: "r", ScorePct: s, Total: 10}
			if err := (store.JSONLTrail{Path: p}).Append(rec); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	_, _, err := runCLI(t, "trend", "--fail-on-regression", trailOf(80, 50))
	wantExit(t, err, 3)
	for _, scores := range [][]int{{50, 80}, {60, 60}, {40}} {
		if _, _, err := runCLI(t, "trend", "--fail-on-regression", trailOf(scores...)); err != nil {
			t.Errorf("scores %v: got %v, want a pass", scores, err)
		}
	}
}

// --format evidence --sign-key signs the document, and verify-evidence pinned
// to that key's fingerprint verifies the file the run wrote.
func TestSignedEvidenceVerifiesAgainstItsPin(t *testing.T) {
	key := writeSigningKey(t)
	out, _, err := runCLI(t, "scan", "--format", "evidence", "--sign-key", key, sampleTree)
	if err != nil {
		t.Fatal(err)
	}
	doc := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(doc, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}

	unpinned, _, err := runCLI(t, "verify-evidence", doc)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(unpinned, "--signer ")
	if i < 0 {
		t.Fatalf("an unpinned check does not offer the fingerprint to pin: %q", unpinned)
	}
	fp := strings.Fields(unpinned[i+len("--signer "):])[0]

	verified, _, err := runCLI(t, "verify-evidence", "--signer", fp, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verified, "VERIFIED") {
		t.Errorf("pinned check of a genuine document: %q", verified)
	}

	if _, _, err := runCLI(t, "verify-evidence", filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("a missing evidence file must be an error")
	}
	if _, _, err := runCLI(t, "scan", "--format", "evidence", "--sign-key", filepath.Join(t.TempDir(), "nokey.pem"), sampleTree); err == nil || !strings.Contains(err.Error(), "load sign key") {
		t.Errorf("an unreadable signing key must be an error, got %v", err)
	}
}

// Test code is set aside by default and the operator is told how much, and how
// much of it exists nowhere else; --include-tests keeps it.
func TestTestCodeIsSetAsideAndCounted(t *testing.T) {
	tree := writeTree(t, map[string]string{
		"prod.go":      md5Source,
		"prod_test.go": md5Source,
		"sha_test.go":  sha1Source,
	})
	out, errOut, err := runCLI(t, "scan", tree)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "2 finding(s) in test code excluded from the production inventory; 1 asset(s) exist only there") {
		t.Errorf("stderr does not count what was set aside: %q", errOut)
	}
	if strings.Contains(out, "SHA-1") {
		t.Errorf("a test-only asset reached the production report: %q", out)
	}

	out, errOut, err = runCLI(t, "scan", "--include-tests", tree)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errOut, "excluded") || !strings.Contains(out, "SHA-1") {
		t.Errorf("--include-tests must keep test code: stdout %q stderr %q", out, errOut)
	}

	// Test code holding only what production also has: nothing exists only there.
	tree = writeTree(t, map[string]string{"prod.go": md5Source, "prod_test.go": md5Source})
	_, errOut, err = runCLI(t, "scan", tree)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "1 finding(s) in test code excluded") || strings.Contains(errOut, "exist only there") {
		t.Errorf("stderr: %q", errOut)
	}
}

// fix prints a diff by default and changes nothing; --write applies it; a floor
// below 2048 is refused; a tree with nothing to fix says so.
func TestFixDiffWriteAndRefusals(t *testing.T) {
	weak, err := os.ReadFile(filepath.Join(sampleTree, "weak.go"))
	if err != nil {
		t.Fatal(err)
	}
	tree := writeTree(t, map[string]string{"weak.go": string(weak)})

	out, errOut, err := runCLI(t, "fix", tree)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "+") || !strings.Contains(out, "3072") {
		t.Errorf("fix did not print a diff raising the key: %q", out)
	}
	if !strings.Contains(errOut, "would change 1 file(s)") {
		t.Errorf("stderr: %q", errOut)
	}
	if got, _ := os.ReadFile(filepath.Join(tree, "weak.go")); string(got) != string(weak) {
		t.Error("fix without --write changed the file")
	}

	_, errOut, err = runCLI(t, "fix", "--write", tree)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(tree, "weak.go")); !strings.Contains(string(got), "3072") {
		t.Errorf("fix --write did not apply the patch: %s", got)
	}
	if !strings.Contains(errOut, "changed 1 file(s)") {
		t.Errorf("stderr: %q", errOut)
	}

	if _, _, err := runCLI(t, "fix", "--min-rsa-bits", "2047", tree); err == nil || !strings.Contains(err.Error(), ">= 2048") {
		t.Errorf("a floor below 2048 must be refused, got %v", err)
	}
	if _, _, err := runCLI(t, "fix", "--min-rsa-bits", "2048", t.TempDir()); err != nil {
		t.Errorf("a floor of exactly 2048 is allowed, got %v", err)
	}
	_, errOut, err = runCLI(t, "fix", t.TempDir())
	if err != nil || !strings.Contains(errOut, "no safe automatic fixes found") {
		t.Errorf("empty tree: err %v stderr %q", err, errOut)
	}
}

// A TLS target that refuses the connection is named on stderr and is not
// counted as scanned, and the run still completes for the others.
func TestTLSReportsAnUnreachableTargetAndCountsOnlyWhatItReached(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	out, errOut, err := runCLI(t, "tls", "--timeout", "2s", addr)
	if err != nil {
		t.Fatalf("an unreachable target must not abort the run: %v", err)
	}
	if !strings.Contains(errOut, addr) {
		t.Errorf("stderr does not name the unreachable target: %q", errOut)
	}
	if !strings.Contains(out, "\n0 sources scanned") {
		t.Errorf("an unreachable target was counted as scanned: %q", out)
	}
}

// bin and image return the connector's error rather than an empty inventory.
func TestBinAndImageReturnTheConnectorError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, _, err := runCLI(t, "bin", missing); err == nil {
		t.Error("bin on a path that does not exist must be an error")
	}
	out, _, err := runCLI(t, "bin", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "\n1 sources scanned, 0 findings") {
		t.Errorf("bin on an empty directory: %q", out)
	}

	notATar := writeTree(t, map[string]string{"img.tar": "this is not a tarball"})
	if _, _, err := runCLI(t, "image", filepath.Join(notATar, "img.tar")); err == nil || !strings.Contains(err.Error(), "img.tar") {
		t.Errorf("image on a non-tarball must be an error naming it, got %v", err)
	}
	if _, _, err := runCLI(t, "agents", missing); err == nil {
		t.Error("agents on a path that does not exist must be an error")
	}
}

// --events writes the agent-event chain: findings, drift and a signed evidence
// event for a source with real agent ids, and a second run resumes the chain
// rather than starting a new one.
func TestEventsAreWrittenAndTheChainResumes(t *testing.T) {
	events := filepath.Join(t.TempDir(), "events.ndjson")
	empty := filepath.Join(t.TempDir(), "empty.json")
	if _, _, err := runCLI(t, "scan", "--save", empty, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	passport := filepath.Join(agentsData, "passport-spiffe.json")

	_, errOut, err := runCLI(t, "agents", "--events", events, "--baseline", empty, "--format", "evidence", "--sign-key", writeSigningKey(t), passport)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "starting a fresh event chain") {
		t.Errorf("stderr: %q", errOut)
	}
	log, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"crypto_finding", "crypto_drift", "evidence_signed"} {
		if !strings.Contains(string(log), typ) {
			t.Errorf("event log carries no %s event: %s", typ, log)
		}
	}

	_, errOut, err = runCLI(t, "agents", "--events", events, passport)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "resumed the event chain") {
		t.Errorf("a second run did not resume the chain: %q", errOut)
	}

	if _, _, err := runCLI(t, "agents", "--events", filepath.Join(t.TempDir(), "no-such-dir", "e.ndjson"), passport); err == nil || !strings.Contains(err.Error(), "open events log") {
		t.Errorf("an events log that cannot be opened must be an error, got %v", err)
	}
}

// A TLS target that answers is counted and its findings reach the report,
// risk-classified like any other source.
func TestTLSCountsAReachedTargetAndReportsWhatItNegotiated(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	out, errOut, err := runCLI(t, "tls", "--timeout", "5s", addr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "\n1 sources scanned") {
		t.Errorf("a reached target was not counted: %q (stderr %q)", out, errOut)
	}
	if !strings.Contains(out, "TLS") {
		t.Errorf("the negotiated protocol is not in the report: %q", out)
	}
}

// image scans each tarball's layers and reports what it found there under an
// image:// root.
func TestImageScansTheLayersOfATarball(t *testing.T) {
	tarOf := func(files map[string]string) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for name, body := range files {
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	layer := tarOf(map[string]string{"app/main.py": "import hashlib\nh = hashlib.md5()\n"})
	img := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(img, tarOf(map[string]string{
		"manifest.json": `[{"Layers":["layer.tar"]}]`,
		"layer.tar":     string(layer),
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := runCLI(t, "image", img)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "image://"+img) || !strings.Contains(out, "MD5") {
		t.Errorf("image report: %q", out)
	}
}

// A postgres:// target selects the Postgres backend, whatever the rest of the
// string looks like. A JSON store at that "path" would not exist and would read
// as a missing baseline, which the plain drift report shrugs off; the Postgres
// backend instead fails to connect, and that must be an error.
func TestAPostgresTargetSelectsThePostgresBackend(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	for _, scheme := range []string{"postgres://", "postgresql://"} {
		url := scheme + "qryx@" + addr + "/qryx?connect_timeout=2"
		if _, _, err := runCLI(t, "scan", "--baseline", url, sampleTree); err == nil || !strings.Contains(err.Error(), "load baseline") {
			t.Errorf("%s baseline: got %v, want a load baseline error", scheme, err)
		}
		if _, _, err := runCLI(t, "trend", url); err == nil {
			t.Errorf("%s trail: an unreachable database must be an error", scheme)
		}
	}
}

// fix --write that cannot write a file says which one and stops.
func TestFixWriteReportsAFileItCouldNotWrite(t *testing.T) {
	weak, err := os.ReadFile(filepath.Join(sampleTree, "weak.go"))
	if err != nil {
		t.Fatal(err)
	}
	tree := writeTree(t, map[string]string{"weak.go": string(weak)})
	if err := os.Chmod(filepath.Join(tree, "weak.go"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "fix", "--write", tree); err == nil || !strings.Contains(err.Error(), "write weak.go") {
		t.Errorf("got %v, want an error naming weak.go", err)
	}
}

// The cloud subcommands name the scope they inventoried in the report's root,
// say on stderr when the inventory is partial, and return a connector error
// rather than an empty inventory.
func TestCloudSubcommandsNameTheirScopeAndSayWhenPartial(t *testing.T) {
	key := model.Finding{
		Asset:    model.Asset{Type: model.TypeKey, Algorithm: "RSA", KeySize: 2048},
		Location: model.Location{File: "key-1"},
		Source:   "aws-kms",
	}
	savedAWS, savedAzure, savedGCP := awsScan, azureScan, gcpScan
	t.Cleanup(func() { awsScan, azureScan, gcpScan = savedAWS, savedAzure, savedGCP })

	var gotRegion, gotProfile, gotVault, gotProject, gotLocation string
	awsScan = func(_ context.Context, region, profile string) ([]model.Finding, []string, error) {
		gotRegion, gotProfile = region, profile
		return []model.Finding{key}, []string{"kms key k2: AccessDenied"}, nil
	}
	azureScan = func(_ context.Context, vault string) ([]model.Finding, []string, error) {
		gotVault = vault
		return []model.Finding{key}, nil, nil
	}
	gcpScan = func(_ context.Context, project, location string) ([]model.Finding, []string, error) {
		gotProject, gotLocation = project, location
		return []model.Finding{key}, nil, nil
	}

	for _, tc := range []struct {
		args     []string
		root     string
		partial  bool
		checkArg func() bool
	}{
		{[]string{"aws"}, "aws://default", true, func() bool { return gotRegion == "" && gotProfile == "" }},
		{[]string{"aws", "--region", "eu-west-2", "--profile", "audit"}, "aws://eu-west-2", true, func() bool { return gotRegion == "eu-west-2" && gotProfile == "audit" }},
		{[]string{"azure", "--vault-url", "https://v.vault.azure.net/"}, "azure://https://v.vault.azure.net/", false, func() bool { return gotVault == "https://v.vault.azure.net/" }},
		{[]string{"gcp", "--project", "p1"}, "gcp://p1/-", false, func() bool { return gotProject == "p1" && gotLocation == "-" }},
		{[]string{"gcp", "--project", "p1", "--location", "europe-west2"}, "gcp://p1/europe-west2", false, func() bool { return gotLocation == "europe-west2" }},
	} {
		out, errOut, err := runCLI(t, tc.args...)
		if err != nil {
			t.Errorf("%v: %v", tc.args, err)
			continue
		}
		if !tc.checkArg() {
			t.Errorf("%v: the connector was not handed the scope the operator typed", tc.args)
		}
		if !strings.Contains(out, "qryx scan: "+tc.root+"\n") || !strings.Contains(out, "RSA-2048") {
			t.Errorf("%v: report does not name root %s or carry the key: %q", tc.args, tc.root, out)
		}
		if got := strings.Contains(errOut, "This inventory is partial"); got != tc.partial {
			t.Errorf("%v: partial-inventory line present=%v, want %v: %q", tc.args, got, tc.partial, errOut)
		}
	}

	boom := errors.New("listing denied")
	awsScan = func(context.Context, string, string) ([]model.Finding, []string, error) { return nil, nil, boom }
	azureScan = func(context.Context, string) ([]model.Finding, []string, error) { return nil, nil, boom }
	gcpScan = func(context.Context, string, string) ([]model.Finding, []string, error) { return nil, nil, boom }
	for _, args := range [][]string{{"aws"}, {"azure", "--vault-url", "https://v/"}, {"gcp", "--project", "p"}} {
		if _, _, err := runCLI(t, args...); !errors.Is(err, boom) {
			t.Errorf("%v: got %v, want the connector's error", args, err)
		}
	}
}
