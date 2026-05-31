package attest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// writeKey marshals a private key to a PKCS#8 PEM file and returns its path.
func writeKey(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func ed25519Key(t *testing.T) any {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func ecdsaKey(t *testing.T) any {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestSignVerifyRoundtrip(t *testing.T) {
	for name, gen := range map[string]func(*testing.T) any{"ed25519": ed25519Key, "ecdsa": ecdsaKey} {
		t.Run(name, func(t *testing.T) {
			signer, err := LoadSigner(writeKey(t, gen(t)))
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("sha256:deadbeef")
			sig, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(payload, sig); err != nil {
				t.Errorf("verify failed: %v", err)
			}
			if Fingerprint(sig) == "sha256:invalid" {
				t.Error("fingerprint should be valid")
			}
		})
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	signer, err := LoadSigner(writeKey(t, ed25519Key(t)))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign([]byte("sha256:original"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte("sha256:tampered"), sig); err == nil {
		t.Fatal("tampered payload must fail verification")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	a, err := LoadSigner(writeKey(t, ed25519Key(t)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadSigner(writeKey(t, ed25519Key(t)))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("sha256:x")
	sig, err := a.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	// Swap in a different key's public key: verification must fail.
	other, _ := b.Sign(payload)
	sig.PublicKey = other.PublicKey
	if err := Verify(payload, sig); err == nil {
		t.Fatal("signature must not verify against a different public key")
	}
}

func TestLoadSignerRejectsUnsupported(t *testing.T) {
	// A non-PEM file.
	bad := filepath.Join(t.TempDir(), "x.pem")
	os.WriteFile(bad, []byte("not a pem"), 0o600)
	if _, err := LoadSigner(bad); err == nil {
		t.Error("non-PEM should error")
	}
}
