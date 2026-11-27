package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sign(t *testing.T, key any, payload []byte) Signature {
	t.Helper()
	s, err := LoadSigner(writeKey(t, key))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// A signature whose declared algorithm does not match the key embedded beside
// it is refused before any verification is attempted. Accepting it would let
// the alg field steer which verifier runs, the classic algorithm-confusion
// shape, and a document's verdict must not depend on a label it carries.
func TestVerifyRefusesAnAlgorithmThatDoesNotMatchTheKey(t *testing.T) {
	payload := []byte("evidence")
	ed := sign(t, ed25519Key(t), payload)
	ec := sign(t, ecdsaKey(t), payload)
	ml := sign(t, mldsaKeyGen(mldsa.MLDSA44())(t), payload)

	for _, tc := range []struct {
		name string
		sig  Signature
		want string
	}{
		{"ed25519 label on an ECDSA key", Signature{Alg: ed.Alg, Value: ec.Value, PublicKey: ec.PublicKey}, "not ed25519"},
		{"ECDSA label on an ed25519 key", Signature{Alg: ec.Alg, Value: ed.Value, PublicKey: ed.PublicKey}, "not ECDSA"},
		{"ML-DSA label on an ECDSA key", Signature{Alg: ml.Alg, Value: ec.Value, PublicKey: ec.PublicKey}, "not ML-DSA"},
	} {
		err := Verify(payload, tc.sig)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error saying %q", tc.name, err, tc.want)
		}
	}
}

// Every malformed field is an error, never a pass, and the error says which
// field it could not read.
func TestVerifyRefusesMalformedSignatures(t *testing.T) {
	payload := []byte("evidence")
	good := sign(t, ecdsaKey(t), payload)
	if err := Verify(payload, good); err != nil {
		t.Fatalf("control: a genuine ECDSA signature must verify: %v", err)
	}
	ml := sign(t, mldsaKeyGen(mldsa.MLDSA65())(t), payload)
	if err := Verify([]byte("evidencf"), ml); err == nil {
		t.Error("an ML-DSA signature over another payload verified")
	}

	for _, tc := range []struct {
		name string
		sig  Signature
		want string
	}{
		{"public key not base64", Signature{Alg: good.Alg, Value: good.Value, PublicKey: "!!"}, "decode public key"},
		{"public key not SPKI", Signature{Alg: good.Alg, Value: good.Value, PublicKey: base64.StdEncoding.EncodeToString([]byte("junk"))}, "parse public key"},
		{"value not base64", Signature{Alg: good.Alg, Value: "!!", PublicKey: good.PublicKey}, "decode signature"},
		{"unknown algorithm", Signature{Alg: "rsa-pss", Value: good.Value, PublicKey: good.PublicKey}, `unsupported signature algorithm "rsa-pss"`},
		{"ECDSA value that is no signature", Signature{Alg: good.Alg, Value: base64.StdEncoding.EncodeToString([]byte{0x30, 0x00}), PublicKey: good.PublicKey}, "verification failed"},
	} {
		err := Verify(payload, tc.sig)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error saying %q", tc.name, err, tc.want)
		}
	}
}

// Only the three supported key kinds load, and ECDSA only on P-256: the
// verifier hashes with SHA-256, and a document signed on another curve would
// claim a strength the pairing does not have.
func TestLoadSignerAcceptsOnlyTheSupportedKeys(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(writeKey(t, p384)); err == nil || !strings.Contains(err.Error(), "P-384") {
		t.Errorf("a P-384 key: got %v, want it refused by curve name", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(writeKey(t, rsaKey)); err == nil || !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("an RSA key: got %v, want it refused", err)
	}

	dir := t.TempDir()
	if _, err := LoadSigner(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("a missing key file must be an error")
	}
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(junk); err == nil || !strings.Contains(err.Error(), "parse PKCS#8 key") {
		t.Errorf("a PEM block that is not PKCS#8: got %v", err)
	}
}

// A signer whose algorithm is not one Sign knows produces no signature rather
// than an unsigned document dressed as a signed one.
func TestSignRefusesAnUnknownAlgorithm(t *testing.T) {
	if _, err := (&Signer{alg: "none"}).Sign([]byte("x")); err == nil {
		t.Fatal("Sign with an unknown algorithm returned a signature")
	}
}

// The fingerprint is shown to a person deciding whether to trust a key, so an
// unreadable key gets a value that cannot be mistaken for one.
func TestFingerprintOfAnUnreadableKey(t *testing.T) {
	if got := Fingerprint(Signature{PublicKey: "!!"}); got != "sha256:invalid" {
		t.Errorf("got %q", got)
	}
	a := Fingerprint(sign(t, ed25519Key(t), []byte("x")))
	b := Fingerprint(sign(t, ed25519Key(t), []byte("x")))
	if a == b || !strings.HasPrefix(a, "sha256:") || len(a) != len("sha256:")+16 {
		t.Errorf("two keys gave %q and %q", a, b)
	}
}
