package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
)

// newTLS13Server starts a TLS 1.3 listener that accepts only the given key
// exchange groups (nil: the standard library's defaults, hybrid first).
func newTLS13Server(t *testing.T, curves []tls.CurveID) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "qryx-kex-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func kexFindings(fs []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Asset.Primitive == model.PrimitiveKeyExch {
			out = append(out, f)
		}
	}
	return out
}

// The probe reports the group the session key was actually agreed with. A
// server that takes the hybrid post-quantum group qryx offers first is safe
// from harvest-now-decrypt-later; one that agrees X25519 alone is not.
func TestEndpointReportsTheNegotiatedKeyExchangeGroup(t *testing.T) {
	cases := []struct {
		name   string
		curves []tls.CurveID
		algo   string
		class  model.RiskClass
	}{
		{"hybrid accepted", nil, "X25519MLKEM768", model.RiskNone},
		{"classical only", []tls.CurveID{tls.X25519}, "X25519", model.RiskQuantumVulnerable},
		{"NIST curve only", []tls.CurveID{tls.CurveP256}, "P-256", model.RiskQuantumVulnerable},
	}
	for _, c := range cases {
		addr := newTLS13Server(t, c.curves)
		fs, err := Endpoint(addr, 3*time.Second)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		kex := kexFindings(risk.Apply(fs))
		if len(kex) != 1 {
			t.Fatalf("%s: %d key-exchange findings, want one: %+v", c.name, len(kex), kex)
		}
		if kex[0].Asset.Algorithm != c.algo || kex[0].Risk.Class != c.class || kex[0].Location.File != addr || kex[0].Source != "tls-probe" {
			t.Fatalf("%s: got %q %q at %q from %q, want %q %q", c.name, kex[0].Asset.Algorithm, kex[0].Risk.Class, kex[0].Location.File, kex[0].Source, c.algo, c.class)
		}
	}
}

// The group is named from its IANA code point, not from the toolchain's own
// name for it: a hybrid this Go release cannot name must still read as hybrid,
// and the central classifier, which knows no "X25519", must never be the one
// that decides a classical group is safe.
func TestKexGroupFinding(t *testing.T) {
	cases := []struct {
		id    tls.CurveID
		ok    bool
		algo  string
		class model.RiskClass
		sev   model.Severity
	}{
		{0x11EC, true, "X25519MLKEM768", model.RiskNone, model.SeverityNone},
		{0x11EB, true, "SecP256r1MLKEM768", model.RiskNone, model.SeverityNone},
		{0x11ED, true, "SecP384r1MLKEM1024", model.RiskNone, model.SeverityNone},
		{tls.X25519, true, "X25519", model.RiskQuantumVulnerable, model.SeverityHigh},
		{tls.CurveP256, true, "P-256", model.RiskQuantumVulnerable, model.SeverityHigh},
		{tls.CurveP384, true, "P-384", model.RiskQuantumVulnerable, model.SeverityHigh},
		{tls.CurveP521, true, "P-521", model.RiskQuantumVulnerable, model.SeverityHigh},
		{0x1234, true, "group 0x1234", "", model.SeverityNone},
		{0, false, "", "", model.SeverityNone},
	}
	for _, c := range cases {
		f, ok := kexGroupFinding("h:443", c.id)
		if ok != c.ok {
			t.Errorf("0x%04x: ok %v, want %v", uint16(c.id), ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if f.Asset.Algorithm != c.algo || f.Risk.Class != c.class || f.Risk.Severity != c.sev || f.Asset.Primitive != model.PrimitiveKeyExch {
			t.Errorf("0x%04x: %q %q/%v, want %q %q/%v", uint16(c.id), f.Asset.Algorithm, f.Risk.Class, f.Risk.Severity, c.algo, c.class, c.sev)
		}
		if c.class == model.RiskQuantumVulnerable && f.Risk.Reason == "" {
			t.Errorf("0x%04x: no reason given", uint16(c.id))
		}
	}
}
