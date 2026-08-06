package detectors

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
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

// TestDepsDetectsCryptoLibs: each library is inventoried under its own name.
// It used to assert that pycryptodome produced an "AES" asset, which is the
// defect in TestDepsManifestEntryIsNotAnAlgorithmAsset below, written down as
// an expectation: a manifest entry names a library, and only the code can say
// which primitives it uses.
func TestDepsDetectsCryptoLibs(t *testing.T) {
	content := []byte("flask==3.0\npycryptodome==3.20\nbcrypt>=4.0\n")
	got := NewDeps().Detect(scan.File{Path: "requirements.txt", Content: content})
	libs := map[string]bool{}
	for _, f := range got {
		if f.Asset.Type != model.TypeLibrary {
			t.Errorf("expected library asset, got %v", f.Asset.Type)
		}
		libs[f.Asset.Algorithm] = true
	}
	if !libs["pycryptodome"] || !libs["bcrypt"] {
		t.Fatalf("expected pycryptodome and bcrypt findings, got %+v", got)
	}
}

// TestDepsManifestEntryIsNotAnAlgorithmAsset pins what a dependency manifest
// can and cannot say. `cryptography>=42` in a requirements.txt is a library
// that MIGHT use RSA, among a dozen other primitives, and might never be
// called. It used to be mapped to algorithm "RSA", and because risk.Classify
// keys purely on the algorithm name with no regard for asset type, that line
// became a quantum-vulnerable HIGH asset: counted against the CNSA 2.0 score,
// listed in the NCSC 2035 migration set, and able to trip `--fail-on high`.
// The manifest never said any of that.
func TestDepsManifestEntryIsNotAnAlgorithmAsset(t *testing.T) {
	content := []byte("flask==3.0\ncryptography>=42\n")
	got := risk.Apply(NewDeps().Detect(scan.File{Path: "requirements.txt", Content: content}))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Asset.Algorithm == "RSA" {
		t.Errorf("a manifest naming %q was reported as an RSA asset", "cryptography")
	}
	if f.Asset.Algorithm != "cryptography" {
		t.Errorf("algorithm=%q, want the library's own name %q", f.Asset.Algorithm, "cryptography")
	}
	if f.Asset.Type != model.TypeLibrary {
		t.Errorf("type=%q, want %q", f.Asset.Type, model.TypeLibrary)
	}
	if f.Risk.Class != model.RiskNone {
		t.Errorf("risk class=%q, want %q: a declared dependency is inventory, not a graded weakness", f.Risk.Class, model.RiskNone)
	}
	if f.Risk.Severity != model.SeverityInfo {
		t.Errorf("severity=%q, want info", f.Risk.Severity)
	}
	if f.Location.Line != 2 {
		t.Errorf("line=%d, want 2", f.Location.Line)
	}
	if !strings.Contains(f.Evidence, "cryptography") {
		t.Errorf("evidence %q does not name the library", f.Evidence)
	}
}

// TestDepsReportsEveryDeclarationOncePerLine covers the other half: the
// detector used strings.Index, so only the first mention of a library in a
// file was ever reported, and the "openssl" needle matched inside the
// "pyopenssl" line, inventing a second dependency that is not there.
func TestDepsReportsEveryDeclarationOncePerLine(t *testing.T) {
	pkg := []byte(`{
  "dependencies": { "node-forge": "^1.3.1" },
  "devDependencies": { "node-forge": "^1.3.1" }
}`)
	got := NewDeps().Detect(scan.File{Path: "package.json", Content: pkg})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (both declarations): %+v", len(got), got)
	}
	lines := []int{got[0].Location.Line, got[1].Location.Line}
	sort.Ints(lines)
	if lines[0] != 2 || lines[1] != 3 {
		t.Errorf("lines=%v, want [2 3]", lines)
	}

	one := NewDeps().Detect(scan.File{Path: "requirements.txt", Content: []byte("pyopenssl==24.0\n")})
	if len(one) != 1 {
		t.Fatalf("got %d findings for one pyopenssl line, want 1: %+v", len(one), one)
	}
	if one[0].Asset.Algorithm != "pyopenssl" {
		t.Errorf("algorithm=%q, want the most specific name on the line, %q", one[0].Asset.Algorithm, "pyopenssl")
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

// TestCryptoCallIgnoresPythonCommentsAndStrings pins the same property the
// rust detector has had since it was written, and that the README claims for
// that row: prose about cryptography is not a use of cryptography. The Python
// patterns are identifiers (\bRSA\b, \bDES\b, \bAES\b), and they used to run
// against raw file content, so a comment saying "migrate off RSA" produced an
// RSA quantum-vulnerable finding and a docstring naming DES produced a weak
// one. CLAUDE.md's detector rule is explicit: don't scrape strings, keep false
// positives low.
func TestCryptoCallIgnoresPythonCommentsAndStrings(t *testing.T) {
	src := []byte(`# TODO: migrate off RSA before 2030
"""This module used to use DES.

Do not use DSA here either.
"""
NOTE = "AES is fine, ChaCha20 is fine"
import hashlib


def digest(data):
    return hashlib.sha256(data)
`)
	got := NewCryptoCall().Detect(scan.File{Path: "notes.py", Content: src})
	algos := map[string]int{}
	for _, f := range got {
		algos[f.Asset.Algorithm] = f.Location.Line
	}
	for _, prose := range []string{"RSA", "DES", "DSA", "AES", "ChaCha20"} {
		if line, found := algos[prose]; found {
			t.Errorf("%s found at line %d, but it appears only in a comment, a docstring or a string literal", prose, line)
		}
	}
	if algos["SHA-256"] != 11 {
		t.Errorf("real hashlib.sha256 call reported at line %d, want 11 (line numbers must survive stripping): %+v", algos["SHA-256"], algos)
	}
}

// TestCryptoCallIgnoresJSComments is the JS/TS half. Note what it does NOT
// ask for: node's crypto API takes the algorithm name as a string literal
// (createHash('md5')), so those patterns must keep matching inside literals.
// Comments are the part that is never code in either language.
func TestCryptoCallIgnoresJSComments(t *testing.T) {
	src := []byte(`// we used to call crypto.createHash('md5') here
/*
 * and crypto.createCipheriv('des', ...) before that
 */
const h = crypto.createHash('sha256');
`)
	got := NewCryptoCall().Detect(scan.File{Path: "hash.js", Content: src})
	algos := map[string]int{}
	for _, f := range got {
		algos[f.Asset.Algorithm] = f.Location.Line
	}
	if line, found := algos["MD5"]; found {
		t.Errorf("MD5 found at line %d, but it appears only in a line comment", line)
	}
	if line, found := algos["DES"]; found {
		t.Errorf("DES found at line %d, but it appears only in a block comment", line)
	}
	if algos["SHA-256"] != 5 {
		t.Errorf("real createHash('sha256') reported at line %d, want 5: %+v", algos["SHA-256"], algos)
	}
}

// TestCryptoCallUnterminatedQuoteDoesNotHideTheFile guards the direction of
// the trade this fix makes. A quote that never closes, in a broken or partial
// file a scanner does not get to refuse, would send a naive stripper blanking
// to the end of the file: every finding after it vanishes and the scan reports
// clean. Neither language lets a '...' or "..." span a line, so the newline
// ends it and the code below is still examined. CLAUDE.md invariant 6: a clean
// scan must never be manufactured by not looking.
func TestCryptoCallUnterminatedQuoteDoesNotHideTheFile(t *testing.T) {
	py := []byte("label = 'unterminated\nkey = RSA.generate(2048)\n")
	var sawRSA bool
	for _, f := range NewCryptoCall().Detect(scan.File{Path: "broken.py", Content: py}) {
		if f.Asset.Algorithm == "RSA" && f.Location.Line == 2 {
			sawRSA = true
		}
	}
	if !sawRSA {
		t.Errorf("the RSA call on line 2 was hidden by an unterminated quote on line 1")
	}

	// The same shape in JSX, where an apostrophe in prose is ordinary text.
	jsx := []byte(`export function Note() {
  return <p>don't roll your own crypto</p>;
}
const legacy = crypto.createHash('md5');
`)
	var sawMD5 bool
	for _, f := range NewCryptoCall().Detect(scan.File{Path: "Note.jsx", Content: jsx}) {
		if f.Asset.Algorithm == "MD5" && f.Location.Line == 4 {
			sawMD5 = true
		}
	}
	if !sawMD5 {
		t.Errorf("the md5 call on line 4 was hidden by an apostrophe on line 2")
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

// The same rule for certificates: a PEM block x509 rejects is skipped, and a
// skipped certificate must not be indistinguishable from a file that held no
// certificate at all.
func TestCertFileCountsAPEMBlockItCouldNotParse(t *testing.T) {
	c := NewCertFile()
	garbage := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})

	if got := c.Detect(scan.File{Path: "broken.pem", Content: garbage}); len(got) != 0 {
		t.Fatalf("expected no findings from an unparsable certificate, got %d", len(got))
	}
	if c.Unparsed() != 1 {
		t.Errorf("Unparsed() = %d, want 1: the rejected certificate was swallowed", c.Unparsed())
	}
}
