package main

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/attest"
	"github.com/TAIPANBOX/qryx/internal/report"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// signedEvidence returns a signed evidence document and the fingerprint of the
// key that signed it. Each call uses a fresh key, so two calls give two signers.
func signedEvidence(t *testing.T) ([]byte, string) {
	t.Helper()
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
	sig, err := report.Evidence(&buf, &scan.Result{Root: "testdata"}, "test", signer)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), attest.Fingerprint(*sig)
}

// TestVerifyEvidenceCIModeRefusesWithoutAPin holds F-020's second half. In CI
// mode a consistent, self-signed document is not a pass when nobody named the
// signer: the check refuses, says why, and prints no verdict to read as one.
func TestVerifyEvidenceCIModeRefusesWithoutAPin(t *testing.T) {
	doc, _ := signedEvidence(t)
	var out bytes.Buffer
	err := verifyEvidence(&out, doc, "", true)
	if err == nil {
		t.Fatalf("CI mode passed an evidence check with no signer pinned, printing %q", out.String())
	}
	if !strings.Contains(err.Error(), "no signer pinned") {
		t.Errorf("CI refusal does not say why: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("CI refusal still printed a verdict: %q", out.String())
	}
}

// TestVerifyEvidenceUnpinnedIsNotVerified: outside CI mode the same unpinned
// check is still allowed, but it is reported as not verified, never as VERIFIED.
func TestVerifyEvidenceUnpinnedIsNotVerified(t *testing.T) {
	doc, fp := signedEvidence(t)
	var out bytes.Buffer
	if err := verifyEvidence(&out, doc, "", false); err != nil {
		t.Fatalf("outside CI mode an unpinned check is reported, not refused: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "not verified: no signer pinned") {
		t.Errorf("unpinned output %q does not say not verified", got)
	}
	if strings.Contains(got, "VERIFIED") {
		t.Errorf("unpinned output %q carries the word VERIFIED", got)
	}
	if !strings.Contains(got, fp) {
		t.Errorf("unpinned output %q does not name the key to pin (%s)", got, fp)
	}
}

// TestVerifyEvidenceCIModeAcceptsThePinnedSigner: the one path that passes in
// CI mode is a document signed by the key the caller named.
func TestVerifyEvidenceCIModeAcceptsThePinnedSigner(t *testing.T) {
	doc, fp := signedEvidence(t)
	var out bytes.Buffer
	if err := verifyEvidence(&out, doc, fp, true); err != nil {
		t.Fatalf("pinned CI check of the real signer failed: %v", err)
	}
	if !strings.Contains(out.String(), "VERIFIED") {
		t.Errorf("pinned output %q does not say VERIFIED", out.String())
	}
}

// TestVerifyEvidenceCIRejectsAForgeryResignedByAnotherKey is the forgery the
// finding describes: a document rewritten and re-signed by another key is
// internally consistent, so only a pinned signer can tell it apart.
func TestVerifyEvidenceCIRejectsAForgeryResignedByAnotherKey(t *testing.T) {
	_, legit := signedEvidence(t)
	forged, _ := signedEvidence(t)

	var out bytes.Buffer
	if err := verifyEvidence(&out, forged, legit, true); err == nil {
		t.Fatal("a document re-signed by another key passed a CI check pinned to the real signer")
	}
	out.Reset()
	if err := verifyEvidence(&out, forged, "", true); err == nil {
		t.Fatalf("a re-signed document passed an unpinned CI check, printing %q", out.String())
	}
	if out.Len() != 0 {
		t.Errorf("forgery refusal still printed a verdict: %q", out.String())
	}
}

// TestVerifyEvidenceWrongPinFailsInEveryMode: a pin that names a different key
// is a refusal whether or not CI mode is on.
func TestVerifyEvidenceWrongPinFailsInEveryMode(t *testing.T) {
	doc, _ := signedEvidence(t)
	_, other := signedEvidence(t)
	for _, ci := range []bool{false, true} {
		var out bytes.Buffer
		if err := verifyEvidence(&out, doc, other, ci); err == nil {
			t.Errorf("ci=%v: a pin to another key passed, printing %q", ci, out.String())
		}
	}
}
