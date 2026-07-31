package detectors

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/scan"
)

func rustScan(t *testing.T, src string) map[string]int {
	t.Helper()
	got := NewRust().Detect(scan.File{Path: "lib.rs", Content: []byte(src)})
	found := make(map[string]int, len(got))
	for _, f := range got {
		found[f.Asset.Algorithm] = f.Location.Line
	}
	return found
}

func TestRustDetectsHandWrittenAndCrateIdioms(t *testing.T) {
	src := `use p384::EcdsaP384;
fn sign(d: &[u8]) -> Vec<u8> {
    let h = Sha384::digest(d);
    let k = MlKem768::new();
    let c = Aes256Gcm::new(&k);
    hmac_sha256(&h, d)
}
`
	found := rustScan(t, src)
	for _, want := range []string{"ECDSA", "SHA-384", "ML-KEM", "AES", "HMAC"} {
		if _, ok := found[want]; !ok {
			t.Errorf("missed %s in ordinary Rust: %v", want, found)
		}
	}
}

// The reason this detector strips before matching, and the reason it is not simply
// `.rs` added to the regex table in cryptocall.go.
//
// A file that explains an algorithm is not a file that uses one. The codebase this
// was written for carries paragraphs about why ECDSA is quantum-vulnerable in the
// doc comment above code that does something else entirely, and a detector that
// counted those would report a graph made of prose.
func TestRustIgnoresCommentsAndStrings(t *testing.T) {
	src := `//! This module explains that ECDSA is quantum-vulnerable and MD5 is broken.
/* RSA and DES appear here too, in a block comment. */
fn describe() -> &'static str {
    "SHA-1 and RC4 named in a string literal"
}
`
	found := rustScan(t, src)
	if len(found) != 0 {
		t.Fatalf("prose was reported as usage: %v", found)
	}
}

// A lifetime is not a character literal. Getting this wrong blanks the rest of the
// file from the first `'a` onwards, which hides every real finding after it and
// looks exactly like a clean scan.
func TestRustLifetimesDoNotSwallowTheFile(t *testing.T) {
	src := `fn borrow<'a>(x: &'a str) -> &'a str { x }
fn later() { let _ = Sha256::digest(b""); }
`
	found := rustScan(t, src)
	if _, ok := found["SHA-256"]; !ok {
		t.Fatalf("a lifetime hid the rest of the file: %v", found)
	}
}

// Blanking rather than deleting, checked where it matters: a line number that
// pointed into a shortened copy of the file would send a reader to the wrong place
// with complete confidence.
func TestRustLineNumbersSurviveStripping(t *testing.T) {
	src := `// one
/* two
   three */
fn f() {
    let _ = Sha512::digest(b"");
}
`
	found := rustScan(t, src)
	if got := found["SHA-512"]; got != 5 {
		t.Fatalf("line %d, want 5", got)
	}
}

func TestRustRawStringsAreNotCode(t *testing.T) {
	src := `fn f() -> &'static str { r#"ECDSA and MD5 inside a raw string"# }
fn g() { let _ = Sha256::digest(b""); }
`
	found := rustScan(t, src)
	if _, bad := found["ECDSA"]; bad {
		t.Errorf("a raw string was read as code: %v", found)
	}
	if _, ok := found["SHA-256"]; !ok {
		t.Errorf("the raw string swallowed the code after it: %v", found)
	}
}

// Post-quantum algorithms are recognised rather than merely not flagged, so a
// codebase that has migrated shows the migration instead of an empty graph.
func TestRustCreditsPostQuantum(t *testing.T) {
	found := rustScan(t, "fn f() { let _ = MlDsa87::new(); let _ = ML_KEM_768; }\n")
	for _, want := range []string{"ML-DSA", "ML-KEM"} {
		if _, ok := found[want]; !ok {
			t.Errorf("missed %s: %v", want, found)
		}
	}
}

func TestRustWantsOnlyRustFiles(t *testing.T) {
	r := NewRust()
	if !r.Wants("src/lib.rs") {
		t.Error("should want .rs")
	}
	if r.Wants("main.go") || r.Wants("setup.py") {
		t.Error("should not want other languages, which have their own detectors")
	}
}
