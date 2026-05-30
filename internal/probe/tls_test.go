package probe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
)

// newTLSServer starts a TLS listener with a self-signed RSA cert of the given
// bit size and returns its address. The listener closes when the test ends.
func newTLSServer(t *testing.T, bits int, minVer uint16) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "qryx-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVer,
		MaxVersion:   minVer,
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
			tc := c.(*tls.Conn)
			_ = tc.Handshake()
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func TestEndpointReportsCertKeyAndVersion(t *testing.T) {
	addr := newTLSServer(t, 1024, tls.VersionTLS12)

	findings, err := Endpoint(addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	findings = risk.Apply(findings)

	var sawTLS, sawWeakRSA bool
	for _, f := range findings {
		if f.Location.File != addr {
			t.Errorf("location = %q, want %q", f.Location.File, addr)
		}
		if f.Asset.Type == model.TypeProtocol && f.Asset.Algorithm == "TLS" {
			sawTLS = true
		}
		// RSA-1024 cert key: classified weak (below 2048) after risk.Apply.
		if f.Asset.Type == model.TypeCertificate && f.Asset.Algorithm == "RSA" {
			if f.Asset.KeySize != 1024 {
				t.Errorf("cert key size = %d, want 1024", f.Asset.KeySize)
			}
			if f.Risk.Class != model.RiskWeak {
				t.Errorf("RSA-1024 risk = %q, want weak", f.Risk.Class)
			}
			sawWeakRSA = true
		}
	}
	if !sawTLS {
		t.Error("expected a TLS protocol finding")
	}
	if !sawWeakRSA {
		t.Error("expected an RSA certificate finding")
	}
}

func TestEndpointFlagsLegacyTLSVersion(t *testing.T) {
	addr := newTLSServer(t, 2048, tls.VersionTLS11)

	findings, err := Endpoint(addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	var flagged bool
	for _, f := range findings {
		if f.Asset.Algorithm == "TLS" && f.Risk.Class == model.RiskMisconfig {
			flagged = true
		}
	}
	if !flagged {
		t.Error("expected TLS 1.1 to be flagged as misconfig")
	}
}
