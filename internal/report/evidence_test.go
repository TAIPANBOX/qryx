package report

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/attest"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

func evidenceFixture() *scan.Result {
	return &scan.Result{Root: "testdata", Findings: []model.Finding{
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "MD5", Primitive: model.PrimitiveHash}, Location: model.Location{File: "a.go", Line: 1}, Source: "goast", Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityHigh}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 1024, Primitive: model.PrimitiveSignature}, Location: model.Location{File: "b.go", Line: 2}, Source: "goast", Risk: model.Risk{Class: model.RiskWeak, Severity: model.SeverityCritical}},
		{Asset: model.Asset{Type: model.TypeAlgorithm, Algorithm: "AES", KeySize: 256, Primitive: model.PrimitiveEncryption}, Location: model.Location{File: "c.go", Line: 3}, Source: "goast", Risk: model.Risk{Class: model.RiskNone}},
	}}
}

func decodeEvidence(t *testing.T, res *scan.Result) (evidenceReport, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if _, err := Evidence(&buf, res, "test-1.0", nil); err != nil {
		t.Fatal(err)
	}
	var rep evidenceReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return rep, buf.Bytes()
}

func TestEvidenceSummaryAndMeta(t *testing.T) {
	rep, _ := decodeEvidence(t, evidenceFixture())

	if rep.Tool != "qryx" || rep.Version != "test-1.0" || rep.Standard != "CNSA 2.0" {
		t.Errorf("metadata wrong: %+v", rep)
	}
	if rep.Summary.Total != 3 {
		t.Errorf("total=%d want 3", rep.Summary.Total)
	}
	// MD5 + RSA-1024 are non-compliant; AES-256 is compliant.
	if rep.Summary.NonCompliant != 2 || rep.Summary.Compliant != 1 {
		t.Errorf("compliant=%d nonCompliant=%d", rep.Summary.Compliant, rep.Summary.NonCompliant)
	}
	if rep.Summary.ScorePct != 33 {
		t.Errorf("scorePct=%d want 33", rep.Summary.ScorePct)
	}
	// bySeverity excludes the RiskNone AES asset.
	if rep.Summary.BySeverity["critical"] != 1 || rep.Summary.BySeverity["high"] != 1 {
		t.Errorf("bySeverity=%v", rep.Summary.BySeverity)
	}
	if _, ok := rep.Summary.BySeverity["none"]; ok {
		t.Errorf("RiskNone assets must not appear in bySeverity: %v", rep.Summary.BySeverity)
	}
}

// TestAttestCarriesNotAssessed pins the count on the way out of the report
// package. Attest is the only path by which the evidence trail learns a scan's
// numbers, so a summary that splits four ways and an Attestation that splits
// three ways means the trail can never show the split: a reader of `qryx trend`
// would have to subtract to discover that the denominator holds ungraded
// assets, and subtraction is not a thing a reader of a compliance record should
// have to do to find out what it says.
func TestAttestCarriesNotAssessed(t *testing.T) {
	res := evidenceFixture()
	// SHA-256 is not on the CNSA 2.0 list, so it is graded "not-assessed".
	res.Findings = append(res.Findings, model.Finding{
		Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "SHA-256", Primitive: model.PrimitiveHash},
		Location: model.Location{File: "d.go", Line: 4},
		Source:   "goast",
		Risk:     model.Risk{Class: model.RiskNone},
	})

	att, err := Attest(res, "test-1.0")
	if err != nil {
		t.Fatal(err)
	}
	if att.NotAssessed != 1 {
		t.Errorf("Attestation.NotAssessed = %d, want 1", att.NotAssessed)
	}
	if sum := att.Compliant + att.NonCompliant + att.Issues + att.NotAssessed; sum != att.Total {
		t.Errorf("counts sum to %d but Total = %d: an attestation whose parts do not "+
			"add up to its whole cannot be read without guessing what the gap is (%+v)", sum, att.Total, att)
	}
}

func TestEvidenceDigestVerifies(t *testing.T) {
	rep, _ := decodeEvidence(t, evidenceFixture())

	if !strings.HasPrefix(rep.Digest, "sha256:") {
		t.Fatalf("digest=%q", rep.Digest)
	}
	// Recompute with the field blanked, as a verifier would.
	embedded := strings.TrimPrefix(rep.Digest, "sha256:")
	rep.Digest = ""
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != embedded {
		t.Errorf("digest mismatch: embedded %s, recomputed %s", embedded, got)
	}
}

func TestEvidenceSignAndVerify(t *testing.T) {
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
	sig, err := Evidence(&buf, evidenceFixture(), "v", signer)
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil || sig.Alg != "ed25519" {
		t.Errorf("Evidence returned signature = %+v, want a non-nil ed25519 signature", sig)
	}
	signed := buf.Bytes()

	alg, fp, err := VerifyEvidence(signed)
	if err != nil {
		t.Fatalf("signed evidence should verify: %v", err)
	}
	if alg != "ed25519" || fp == "" {
		t.Errorf("alg=%q fp=%q", alg, fp)
	}

	// Mutating the document breaks verification.
	mutated := bytes.Replace(signed, []byte(`"version": "v"`), []byte(`"version": "x"`), 1)
	if _, _, err := VerifyEvidence(mutated); err == nil {
		t.Error("mutated evidence must not verify")
	}

	// Unsigned evidence is reported as such.
	var unsigned bytes.Buffer
	if _, err := Evidence(&unsigned, evidenceFixture(), "v", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyEvidence(unsigned.Bytes()); err == nil {
		t.Error("unsigned evidence should report not signed")
	}
}

func TestEvidenceDigestStable(t *testing.T) {
	// Same input (with generatedAt normalized) yields the same digest.
	a, _ := decodeEvidence(t, evidenceFixture())
	b, _ := decodeEvidence(t, evidenceFixture())
	a.GeneratedAt, b.GeneratedAt = "", ""
	da, _ := evidenceDigest(a)
	db, _ := evidenceDigest(b)
	if da != db {
		t.Errorf("digest not stable: %s vs %s", da, db)
	}
}
