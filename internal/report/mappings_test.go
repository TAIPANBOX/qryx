package report

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/attest"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/store"
)

// The drift section says "none" only when nothing moved, and otherwise lists
// each new and each removed asset with its key size, so a reviewer can see
// RSA-1024 appear rather than "RSA".
func TestDriftListsWhatWasAddedAndRemoved(t *testing.T) {
	var buf bytes.Buffer
	Drift(&buf, store.Delta{})
	if !strings.Contains(buf.String(), "Drift vs baseline: none") {
		t.Errorf("empty delta: %q", buf.String())
	}

	node := func(algo string, bits int, file string) graph.AssetNode {
		return graph.AssetNode{
			Asset:       model.Asset{Type: model.TypeKey, Algorithm: algo, KeySize: bits},
			Risk:        model.Risk{Class: model.RiskWeak, Severity: model.SeverityCritical},
			Occurrences: []graph.Occurrence{{Location: model.Location{File: file, Line: 3}}},
		}
	}
	buf.Reset()
	Drift(&buf, store.Delta{
		Added:   []graph.AssetNode{node("RSA", 1024, "new.go"), node("MD5", 0, "h.go")},
		Removed: []graph.AssetNode{node("DES", 0, "old.go")},
	})
	out := buf.String()
	for _, want := range []string{"+2 new, -1 removed", "NEW", "RSA-1024", "new.go:3", "REMOVED", "DES", "old.go:3"} {
		if !strings.Contains(out, want) {
			t.Errorf("drift output lacks %q: %q", want, out)
		}
	}
	if strings.Contains(out, "MD5-0") {
		t.Errorf("an asset with no key size was printed with one: %q", out)
	}
}

// The CycloneDX protocol and key-material enums are closed; every name maps to
// a value the schema allows, and the specific one when qryx can tell.
func TestCBOMProtocolAndKeyMaterialTypes(t *testing.T) {
	for in, want := range map[string]string{
		"TLS 1.0": "tls", "SSLv3": "tls", "HTTPS": "tls",
		"ssh": "ssh", "IPsec": "ipsec", "IKEv1": "ike", "WPA2": "wpa", "QUIC": "other",
	} {
		if got := cdxProtocolType(in); got != want {
			t.Errorf("cdxProtocolType(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"private-key": "private-key", "RSA Private Key": "private-key",
		"public-key": "public-key", "AES": "key",
	} {
		if got := cdxKeyMaterialType(in); got != want {
			t.Errorf("cdxKeyMaterialType(%q) = %q, want %q", in, got, want)
		}
	}
}

// Each quantum-vulnerable family gets the CNSA 2.0 replacement for what it
// does: signatures go to ML-DSA, key exchange to ML-KEM, and RSA (which does
// both) names both. An unknown algorithm is not given a specific answer.
func TestQuantumActionNamesTheReplacementForWhatTheAlgorithmDoes(t *testing.T) {
	for in, want := range map[string]string{
		"rsa":   "ML-KEM (key encapsulation) or ML-DSA",
		"ECDSA": "ML-DSA (FIPS 204)", "ecc": "ML-DSA (FIPS 204)", "DSA": "ML-DSA (FIPS 204)",
		"ECDH": "ML-KEM (FIPS 203)", "dh": "ML-KEM (FIPS 203)",
		"ElGamal": "ElGamal is quantum-vulnerable",
	} {
		if got := quantumAction(in); !strings.Contains(got, want) {
			t.Errorf("quantumAction(%q) = %q, want it to say %q", in, got, want)
		}
	}
}

// A container image is a discovery bucket of its own whatever detector found
// the asset in it; elsewhere the source decides, and an unknown source is
// "other" rather than silently counted as code.
func TestNCSCDiscoveryBuckets(t *testing.T) {
	o := graph.Occurrence{Source: "goast"}
	if got := bucketFor("image://app.tar", o); got != "containers" {
		t.Errorf("image root: %q", got)
	}
	if got := bucketFor("/src", o); got != "code" {
		t.Errorf("goast: %q", got)
	}
	if got := bucketFor("/src", graph.Occurrence{Source: "carrier-pigeon"}); got != "other" {
		t.Errorf("unknown source: %q", got)
	}
	for v, want := range map[ncscVerdict]string{verdictOnTrack: "v-ok", verdictAtRisk: "v-risk", verdictNotStarted: "v-none"} {
		if got := verdictClass(v); got != want {
			t.Errorf("verdictClass(%q) = %q, want %q", v, got, want)
		}
	}
}

// The compact location columns show the first place an asset was seen and how
// many more there are, never a bare "+0".
func TestCompactLocationColumns(t *testing.T) {
	for _, tc := range []struct {
		locs []string
		want string
	}{
		{nil, ""},
		{[]string{"a.go:1"}, "a.go:1"},
		{[]string{"a.go:1", "b.go:2", "c.go:3"}, "a.go:1 (+2)"},
	} {
		if got := ncscWhere(ncscFindingJSON{Locations: tc.locs}); got != tc.want {
			t.Errorf("ncscWhere(%v) = %q, want %q", tc.locs, got, tc.want)
		}
	}

	occ := func(file string, line int) graph.Occurrence {
		return graph.Occurrence{Location: model.Location{File: file, Line: line}}
	}
	for _, tc := range []struct {
		occs []graph.Occurrence
		want string
	}{
		{nil, ""},
		{[]graph.Occurrence{occ("k.pem", 0)}, "k.pem"},
		{[]graph.Occurrence{occ("a.go", 4), occ("b.go", 5)}, "a.go:4 (+1)"},
	} {
		if got := dashWhere(cnsaEntry{Node: graph.AssetNode{Occurrences: tc.occs}}); got != tc.want {
			t.Errorf("dashWhere = %q, want %q", got, tc.want)
		}
	}

	if got := shortDigest("sha256:0123456789abcdef"); got != "sha256:0123456789ab" {
		t.Errorf("shortDigest = %q", got)
	}
	if got := shortDigest("sha256:short"); got != "sha256:short" {
		t.Errorf("a digest shorter than the cut must be shown whole, got %q", got)
	}
}

// The owner column reads the common tag conventions in priority order and
// skips an empty value rather than showing a blank owner.
func TestOwnerHintPrefersTheOwnerTag(t *testing.T) {
	for _, tc := range []struct {
		tags map[string]string
		want string
	}{
		{nil, ""},
		{map[string]string{"service": "billing", "Owner": "payments"}, "payments"},
		{map[string]string{"owner": "", "team": "platform"}, "platform"},
		{map[string]string{"Service": "api"}, "api"},
		{map[string]string{"env": "prod"}, ""},
	} {
		if got := ownerHint(tc.tags); got != tc.want {
			t.Errorf("ownerHint(%v) = %q, want %q", tc.tags, got, tc.want)
		}
	}
}

// A forger who edits the document and recomputes its digest, but cannot sign
// with the key inside it, is caught by the signature, not by the digest: the
// digest is arithmetic anybody can redo. The two failures read differently,
// so an operator can tell tampering that was covered up from tampering that
// was not.
func TestVerifyEvidenceRefusesARecomputedDigestUnderTheOldSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := attest.LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := Evidence(&buf, evidenceFixture(), "v", signer); err != nil {
		t.Fatal(err)
	}

	var rep evidenceReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	rep.Version = "forged"
	sum, err := evidenceDigest(rep)
	if err != nil {
		t.Fatal(err)
	}
	rep.Digest = "sha256:" + sum
	forged, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = VerifyEvidence(forged, "")
	if err == nil {
		t.Fatal("a document with a recomputed digest under the old signature verified")
	}
	if strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("the forgery was reported as a digest mismatch, but its digest is consistent: %v", err)
	}

	if _, _, err := VerifyEvidence([]byte("{not json"), ""); err == nil || !strings.Contains(err.Error(), "parse evidence") {
		t.Errorf("non-JSON evidence: got %v", err)
	}
	// A signer that cannot sign produces no document, rather than an unsigned
	// one written where a signed one was asked for.
	var out bytes.Buffer
	if _, err := Evidence(&out, evidenceFixture(), "v", &attest.Signer{}); err == nil || !strings.Contains(err.Error(), "sign evidence") {
		t.Errorf("a signer that fails: got %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("a document was written although signing failed: %q", out.String())
	}
}
