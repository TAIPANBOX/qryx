package detectors

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// --- Hardcoded ---

func TestHardcodedDetectsPrivateKeyInSource(t *testing.T) {
	src := []byte("package x\n\nconst key = `-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----`\n")
	got := NewHardcoded().Detect(scan.File{Path: "creds.go", Content: src})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Risk.Class != model.RiskHardcoded || f.Risk.Severity != model.SeverityCritical {
		t.Errorf("wrong risk: %+v", f.Risk)
	}
	if f.Location.Line != 3 {
		t.Errorf("expected line 3, got %d", f.Location.Line)
	}
}

func TestHardcodedWants(t *testing.T) {
	d := NewHardcoded()
	for path, want := range map[string]bool{
		"main.go": true, "config.yaml": true, ".env": true,
		"server.pem": false, "id_rsa.key": false, "notes.txt": false,
	} {
		if got := d.Wants(path); got != want {
			t.Errorf("Wants(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestHardcodedMultipleKeys(t *testing.T) {
	src := []byte("-----BEGIN EC PRIVATE KEY-----\n...\n-----BEGIN OPENSSH PRIVATE KEY-----\n")
	got := NewHardcoded().Detect(scan.File{Path: "two.py", Content: src})
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}
}

// --- Deps ---

func TestDepsDetectsCryptoLibs(t *testing.T) {
	content := []byte("flask==3.0\npycryptodome==3.20\nbcrypt>=4.0\n")
	got := NewDeps().Detect(scan.File{Path: "requirements.txt", Content: content})
	algos := map[string]bool{}
	for _, f := range got {
		if f.Asset.Type != model.TypeLibrary {
			t.Errorf("expected library asset, got %v", f.Asset.Type)
		}
		algos[f.Asset.Algorithm] = true
	}
	if !algos["AES"] || !algos["bcrypt"] {
		t.Fatalf("expected AES (pycryptodome) and bcrypt findings, got %+v", got)
	}
}

func TestDepsWantsOnlyManifests(t *testing.T) {
	d := NewDeps()
	for path, want := range map[string]bool{
		"go.mod": true, "requirements.txt": true, "package.json": true,
		"Cargo.toml": true, "pom.xml": true,
		"main.go": false, "deps.md": false,
	} {
		if got := d.Wants(path); got != want {
			t.Errorf("Wants(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestDepsNoCryptoNoFindings(t *testing.T) {
	got := NewDeps().Detect(scan.File{Path: "requirements.txt", Content: []byte("requests==2.32\nnumpy\n")})
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(got), got)
	}
}

// --- CryptoCall ---

func TestCryptoCallPython(t *testing.T) {
	src := []byte("import hashlib\nh = hashlib.md5(data)\ns = hashlib.sha256(data)\n")
	got := NewCryptoCall().Detect(scan.File{Path: "hash.py", Content: src})
	algos := map[string]int{}
	for _, f := range got {
		algos[f.Asset.Algorithm] = f.Location.Line
	}
	if algos["MD5"] != 2 || algos["SHA-256"] != 3 {
		t.Fatalf("expected MD5@2 and SHA-256@3, got %+v", algos)
	}
}

func TestCryptoCallJS(t *testing.T) {
	src := []byte("const h = crypto.createHash('sha1');\nconst kp = crypto.generateKeyPairSync('rsa', opts);\n")
	got := NewCryptoCall().Detect(scan.File{Path: "sign.ts", Content: src})
	algos := map[string]bool{}
	for _, f := range got {
		algos[f.Asset.Algorithm] = true
	}
	if !algos["SHA-1"] || !algos["RSA"] {
		t.Fatalf("expected SHA-1 and RSA, got %+v", got)
	}
}

func TestCryptoCallWants(t *testing.T) {
	d := NewCryptoCall()
	for path, want := range map[string]bool{
		"a.py": true, "b.ts": true, "c.jsx": true,
		// Go is deliberately excluded: the AST-based GoAST detector owns it.
		"d.go": false, "e.java": false,
	} {
		if got := d.Wants(path); got != want {
			t.Errorf("Wants(%q) = %v, want %v", path, got, want)
		}
	}
}

// --- CertFile ---

func selfSignedPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "qryx-test"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertFileValidCert(t *testing.T) {
	pemBytes := selfSignedPEM(t, time.Now().Add(365*24*time.Hour))
	got := NewCertFile().Detect(scan.File{Path: "server.pem", Content: pemBytes})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding for valid cert, got %d: %+v", len(got), got)
	}
	if got[0].Asset.Type != model.TypeCertificate || got[0].Asset.Algorithm == "" {
		t.Errorf("unexpected asset: %+v", got[0].Asset)
	}
}

func TestCertFileExpiredCert(t *testing.T) {
	pemBytes := selfSignedPEM(t, time.Now().Add(-time.Hour))
	got := NewCertFile().Detect(scan.File{Path: "old.crt", Content: pemBytes})
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (asset + expiry), got %d: %+v", len(got), got)
	}
	var expired bool
	for _, f := range got {
		if f.Risk.Class == model.RiskExpired && f.Risk.Severity == model.SeverityHigh {
			expired = true
		}
	}
	if !expired {
		t.Fatalf("expected an expired-risk finding, got %+v", got)
	}
}

func TestCertFileGarbageContent(t *testing.T) {
	got := NewCertFile().Detect(scan.File{Path: "junk.pem", Content: []byte("not a pem at all")})
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

// --- TLSConfig ---

func TestTLSConfigGoWeakMinVersion(t *testing.T) {
	src := []byte("cfg := &tls.Config{MinVersion: tls.VersionTLS10}\n")
	got := NewTLSConfig().Detect(scan.File{Path: "srv.go", Content: src})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Algorithm != "TLS 1.0" || f.Risk.Class != model.RiskMisconfig {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestTLSConfigNginxLegacyProtocols(t *testing.T) {
	conf := []byte("ssl_protocols SSLv3 TLSv1 TLSv1.2;\n")
	got := NewTLSConfig().Detect(scan.File{Path: "nginx.conf", Content: conf})
	protos := map[string]bool{}
	for _, f := range got {
		protos[f.Asset.Algorithm] = true
	}
	if !protos["SSL 3.0"] || !protos["TLS 1.0"] {
		t.Fatalf("expected SSL 3.0 and TLS 1.0 findings, got %+v", got)
	}
	if protos["TLS 1.2"] {
		t.Errorf("TLS 1.2 must not be flagged")
	}
}

func TestTLSConfigCleanModernConfig(t *testing.T) {
	src := []byte("cfg := &tls.Config{MinVersion: tls.VersionTLS13}\n")
	got := NewTLSConfig().Detect(scan.File{Path: "srv.go", Content: src})
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(got), got)
	}
}
