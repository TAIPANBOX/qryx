// Package detectors holds the concrete crypto detectors used by the scanner.
package detectors

import (
	"path/filepath"
	"regexp"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// pattern binds a regex to the asset it implies.
type pattern struct {
	re        *regexp.Regexp
	algorithm string
	primitive model.Primitive
}

// patternSet is one language's patterns, split by what they are allowed to
// see. The split exists because the two halves disagree about string
// literals: a Python identifier pattern must not read them, and a Node API
// pattern has nowhere else to read from.
type patternSet struct {
	lang language
	// identifiers match names in code (\bRSA\b, hashlib.md5), so they run
	// against text with comments AND string literals blanked.
	identifiers []pattern
	// literals match a quoted argument (createHash('md5')), so they run
	// against text with only comments blanked.
	literals []pattern
}

// CryptoCall detects cryptographic algorithm usage in Python and JS/TS source
// via API patterns. Go is handled by the AST-based GoAST detector instead, which
// avoids the false positives regex produces on comments and string literals.
type CryptoCall struct {
	patterns map[string]patternSet // ext -> patterns
}

// NewCryptoCall builds the detector with built-in patterns for Python and
// JS/TS. Go is handled by the AST-based GoAST detector, which avoids the false
// positives regex matching produces on comments, docs and string literals.
//
// This detector cannot have an AST, so it gets the next best thing: comments
// and (for the identifier patterns) string literals are blanked before
// matching, the same way rust.go has always done it. Until 5 August 2026 they
// were not, and a Python comment reading "migrate off RSA" produced an RSA
// quantum-vulnerable finding at that line.
func NewCryptoCall() *CryptoCall {
	mk := func(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }

	pyPatterns := []pattern{
		{mk(`hashlib\.md5`), "MD5", model.PrimitiveHash},
		{mk(`hashlib\.sha1`), "SHA-1", model.PrimitiveHash},
		{mk(`hashlib\.sha256`), "SHA-256", model.PrimitiveHash},
		{mk(`hashlib\.sha512`), "SHA-512", model.PrimitiveHash},
		{mk(`\bDES\b`), "DES", model.PrimitiveEncryption},
		{mk(`\bARC4\b|\bRC4\b`), "RC4", model.PrimitiveEncryption},
		{mk(`\bAES\b`), "AES", model.PrimitiveEncryption},
		{mk(`\bRSA\b|rsa\.generate_private_key`), "RSA", model.PrimitiveSignature},
		{mk(`ec\.ECDSA|\bECDSA\b`), "ECDSA", model.PrimitiveSignature},
		{mk(`\bEd25519\b|ed25519`), "Ed25519", model.PrimitiveSignature},
		{mk(`\bDSA\b`), "DSA", model.PrimitiveSignature},
		{mk(`ChaCha20`), "ChaCha20", model.PrimitiveEncryption},
	}

	jsPatterns := []pattern{
		{mk(`createHash\(\s*['"]md5['"]`), "MD5", model.PrimitiveHash},
		{mk(`createHash\(\s*['"]sha1['"]`), "SHA-1", model.PrimitiveHash},
		{mk(`createHash\(\s*['"]sha256['"]`), "SHA-256", model.PrimitiveHash},
		{mk(`createHash\(\s*['"]sha512['"]`), "SHA-512", model.PrimitiveHash},
		{mk(`createCipheriv?\(\s*['"]des`), "DES", model.PrimitiveEncryption},
		{mk(`createCipheriv?\(\s*['"]rc4`), "RC4", model.PrimitiveEncryption},
		{mk(`createCipheriv?\(\s*['"]aes`), "AES", model.PrimitiveEncryption},
		{mk(`generateKeyPair(?:Sync)?\(\s*['"]rsa['"]`), "RSA", model.PrimitiveSignature},
		{mk(`generateKeyPair(?:Sync)?\(\s*['"]ec['"]`), "ECDSA", model.PrimitiveSignature},
		{mk(`generateKeyPair(?:Sync)?\(\s*['"]ed25519['"]`), "Ed25519", model.PrimitiveSignature},
	}

	// Every Python pattern is an identifier; every JS pattern names its
	// algorithm inside a string literal, which is how node's crypto API is
	// called. A new pattern goes in the half that matches how it reads.
	py := patternSet{lang: langPython, identifiers: pyPatterns}
	js := patternSet{lang: langJS, literals: jsPatterns}

	p := map[string]patternSet{
		".py":  py,
		".js":  js,
		".ts":  js,
		".mjs": js,
		".jsx": js,
		".tsx": js,
	}
	return &CryptoCall{patterns: p}
}

func (c *CryptoCall) Name() string { return "cryptocall" }

func (c *CryptoCall) Wants(path string) bool {
	_, ok := c.patterns[filepath.Ext(path)]
	return ok
}

func (c *CryptoCall) Detect(f scan.File) []model.Finding {
	set, ok := c.patterns[filepath.Ext(f.Path)]
	if !ok {
		return nil
	}
	var out []model.Finding
	if len(set.identifiers) > 0 {
		out = append(out, c.match(f, stripNonCode(f.Content, set.lang, true), set.identifiers)...)
	}
	if len(set.literals) > 0 {
		out = append(out, c.match(f, stripNonCode(f.Content, set.lang, false), set.literals)...)
	}
	return out
}

// match runs one half of a language's patterns over the stripped view they are
// entitled to. Line numbers come from that same view, which is safe because
// stripping only ever replaces a byte, never removes one.
func (c *CryptoCall) match(f scan.File, code []byte, pats []pattern) []model.Finding {
	var out []model.Finding
	for _, p := range pats {
		for _, loc := range p.re.FindAllIndex(code, -1) {
			out = append(out, model.Finding{
				Asset: model.Asset{
					Type:      model.TypeAlgorithm,
					Algorithm: p.algorithm,
					Primitive: p.primitive,
				},
				Location: model.Location{File: f.Path, Line: lineNumber(code, loc[0])},
				Evidence: string(code[loc[0]:loc[1]]),
				Source:   c.Name(),
			})
		}
	}
	return out
}
