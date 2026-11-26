package detectors

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/scan"
)

// An escaped delimiter does not end a string, in any of the three string
// forms the stripper tracks. If it did, the rest of the literal would be read
// as code and a word in it ("gone" here) reported as usage; and the real code
// after it ("keep") must survive with its line intact.
func TestStripNonCodeEscapedDelimitersDoNotEndTheString(t *testing.T) {
	for _, tc := range []struct {
		name string
		lang language
		src  string
	}{
		{"python double", langPython, "s = \"it\\\" gone\"\nkeep()\n"},
		{"python single", langPython, "s = 'it\\' gone'\nkeep()\n"},
		{"python triple", langPython, "s = \"\"\"doc \\\"\"\" gone\"\"\"\nkeep()\n"},
		{"python triple single", langPython, "s = '''a\n''' + 'x'\nkeep()  # gone\n"},
		{"js template", langJS, "s = `a \\` gone`\nkeep()\n"},
		{"js block comment", langJS, "/*/ gone */ keep()\n"},
	} {
		out := stripNonCode([]byte(tc.src), tc.lang, true)
		if len(out) != len(tc.src) || bytes.Count(out, []byte("\n")) != strings.Count(tc.src, "\n") {
			t.Errorf("%s: length or line count changed: %q", tc.name, out)
		}
		if bytes.Contains(out, []byte("gone")) {
			t.Errorf("%s: text inside the literal survived as code: %q", tc.name, out)
		}
		if !bytes.Contains(out, []byte("keep()")) {
			t.Errorf("%s: code after the literal was blanked: %q", tc.name, out)
		}
	}
}

// With literals kept (the Node patterns read their algorithm out of a string),
// a template literal's text stays and only comments go.
func TestStripNonCodeKeepsLiteralsWhenAsked(t *testing.T) {
	src := "h = createHash(`md5`) // sha1 in a comment\n"
	out := string(stripNonCode([]byte(src), langJS, false))
	if !strings.Contains(out, "`md5`") || strings.Contains(out, "sha1") {
		t.Errorf("got %q", out)
	}
}

// The Go detector follows an import alias, sees a crypto package used as a
// value or a type as well as called, and reads an RSA size only from an
// integer literal.
func TestGoASTAliasesValuesAndKeySizes(t *testing.T) {
	src := `package p

import (
	weak "crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"hash"
)

var _ hash.Hash = weak.New()
var _ = weak.Size
var _ *rsa.PublicKey

func k(bits int) {
	_, _ = rsa.GenerateKey(rand.Reader, bits)
	_, _ = rsa.GenerateKey(rand.Reader, 4096)
	_, _ = rsa.GenerateKey(rand.Reader)
	local()
	x.y.z()
}

func local() {}
`
	got := NewGoAST().Detect(scan.File{Path: "p.go", Content: []byte(src)})
	byLine := map[int][]string{}
	for _, f := range got {
		name := f.Asset.Algorithm
		if f.Asset.KeySize > 0 {
			name += "-" + strconv.Itoa(f.Asset.KeySize)
		}
		byLine[f.Location.Line] = append(byLine[f.Location.Line], name)
	}
	want := map[int]string{10: "MD5", 11: "MD5", 12: "RSA", 15: "RSA", 16: "RSA-4096", 17: "RSA"}
	for line, algo := range want {
		if len(byLine[line]) != 1 || byLine[line][0] != algo {
			t.Errorf("line %d: got %v, want [%s]", line, byLine[line], algo)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d findings, want %d: %v", len(got), len(want), byLine)
	}
}
