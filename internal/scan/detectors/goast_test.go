package detectors

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/scan"
)

func TestGoASTIgnoresCommentsAndStrings(t *testing.T) {
	// "crypto/rsa" appears only in a comment and a string literal, never as a
	// real import or call. A regex detector would flag both; the AST detector
	// must report nothing.
	src := []byte(`package x

// This file talks about crypto/rsa but never imports it.
import "fmt"

func f() {
	doc := "see crypto/rsa for details"
	fmt.Println(doc)
}
`)
	got := NewGoAST().Detect(scan.File{Path: "doc.go", Content: src})
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(got), got)
	}
}

func TestGoASTReportsRealUsageWithKeySize(t *testing.T) {
	src := []byte(`package x

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
)

func g() {
	_ = md5.New()
	_, _ = rsa.GenerateKey(rand.Reader, 2048)
}
`)
	got := NewGoAST().Detect(scan.File{Path: "use.go", Content: src})

	byAlgo := map[string]int{}
	for _, f := range got {
		byAlgo[f.Asset.Algorithm] = f.Asset.KeySize
		if _, ok := map[string]bool{"use.go": true}[f.Location.File]; !ok {
			t.Errorf("unexpected location file %q", f.Location.File)
		}
	}
	if _, ok := byAlgo["MD5"]; !ok {
		t.Error("expected MD5 finding")
	}
	if size, ok := byAlgo["RSA"]; !ok {
		t.Error("expected RSA finding")
	} else if size != 2048 {
		t.Errorf("RSA key size = %d, want 2048", size)
	}
}

// A Go file that does not parse yields no findings, which is byte for byte the
// result of a Go file with no cryptography in it. The detector is the only
// place that knows which of the two happened, so it has to say.
func TestGoASTCountsAFileItCouldNotParse(t *testing.T) {
	g := NewGoAST()
	if got := g.Detect(scan.File{Path: "broken.go", Content: []byte("package x\n\nfunc f( {\n")}); len(got) != 0 {
		t.Fatalf("expected no findings from a file that does not parse, got %d", len(got))
	}
	if g.Unparsed() != 1 {
		t.Errorf("Unparsed() = %d, want 1: the parse failure was swallowed", g.Unparsed())
	}

	if got := g.Detect(scan.File{Path: "fine.go", Content: []byte("package x\n")}); len(got) != 0 {
		t.Fatalf("expected no findings from a file with no crypto, got %d", len(got))
	}
	if g.Unparsed() != 1 {
		t.Errorf("Unparsed() = %d after a file that parses cleanly, want 1", g.Unparsed())
	}
}
