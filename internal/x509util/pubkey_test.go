package x509util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// PublicKeyInfo had never been run. It is the function that turns a real
// certificate into the three values everything downstream rates: the algorithm
// name, the key size, and the primitive.
//
// The size is the part with teeth. This is a post-quantum readiness scanner,
// so RSA-2048 and RSA-4096 are different verdicts, and a size read from the
// wrong field or off by a factor is not a crash. It is a report that looks
// exactly like a correct one.
//
// The certificates here are generated rather than fixtured, so the test says
// what it means: not "this blob parses", but "a real 3072-bit RSA key reads as
// 3072".

func certFor(t *testing.T, pub, priv any) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "qryx.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestPublicKeyInfoReadsRealCertificates(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		cert *x509.Certificate
		alg  string
		bits int
		prim model.Primitive
		why  string
	}{
		{
			"RSA carries its modulus length, not a rounded guess",
			certFor(t, &rsaKey.PublicKey, rsaKey),
			"RSA", 3072, model.PrimitiveSignature,
			"3072 is deliberately not the default anybody would hardcode",
		},
		{
			"ECDSA carries the curve's size and not the key's encoding",
			certFor(t, &ecKey.PublicKey, ecKey),
			"ECDSA", 384, model.PrimitiveSignature,
			"P-384 has a 384-bit field; the marshalled point is far longer",
		},
		{
			"Ed25519 is 256 by definition",
			certFor(t, edPub, edPriv),
			"Ed25519", 256, model.PrimitiveSignature,
			"the curve has one size, so this is the one case that is a constant",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			alg, bits, prim := PublicKeyInfo(c.cert)
			if alg != c.alg || bits != c.bits || prim != c.prim {
				t.Fatalf("PublicKeyInfo = (%q, %d, %v), want (%q, %d, %v): %s",
					alg, bits, prim, c.alg, c.bits, c.prim, c.why)
			}
		})
	}
}

// A key this does not recognise must read as unknown and never as a default.
// A zero-bit RSA would be rated by the classifier as if it were an RSA key of
// no size, and the scanner would report a verdict about a key it never
// understood.
func TestAnUnrecognisedKeyIsUnknownAndNotADefault(t *testing.T) {
	alg, bits, prim := PublicKeyInfo(&x509.Certificate{PublicKey: "not a key at all"})
	if alg != "" || bits != 0 || prim != model.PrimitiveUnknown {
		t.Fatalf("PublicKeyInfo on an unrecognised key = (%q, %d, %v), "+
			"want (\"\", 0, PrimitiveUnknown): naming an algorithm here would "+
			"produce a rating for a key nothing understood", alg, bits, prim)
	}
}
