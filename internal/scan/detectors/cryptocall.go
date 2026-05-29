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

// CryptoCall detects cryptographic algorithm usage in Python and JS/TS source
// via API patterns. Go is handled by the AST-based GoAST detector instead, which
// avoids the false positives regex produces on comments and string literals.
type CryptoCall struct {
	patterns map[string][]pattern // ext -> patterns
}

// NewCryptoCall builds the detector with built-in patterns for Python and
// JS/TS. Go is handled by the AST-based GoAST detector, which avoids the false
// positives regex matching produces on comments, docs and string literals.
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

	p := map[string][]pattern{
		".py":  pyPatterns,
		".js":  jsPatterns,
		".ts":  jsPatterns,
		".mjs": jsPatterns,
		".jsx": jsPatterns,
		".tsx": jsPatterns,
	}
	return &CryptoCall{patterns: p}
}

func (c *CryptoCall) Name() string { return "cryptocall" }

func (c *CryptoCall) Wants(path string) bool {
	_, ok := c.patterns[filepath.Ext(path)]
	return ok
}

func (c *CryptoCall) Detect(f scan.File) []model.Finding {
	pats := c.patterns[filepath.Ext(f.Path)]
	var out []model.Finding
	for _, p := range pats {
		for _, loc := range p.re.FindAllIndex(f.Content, -1) {
			line := lineNumber(f.Content, loc[0])
			out = append(out, model.Finding{
				Asset: model.Asset{
					Type:      model.TypeAlgorithm,
					Algorithm: p.algorithm,
					Primitive: p.primitive,
				},
				Location: model.Location{File: f.Path, Line: line},
				Evidence: string(f.Content[loc[0]:loc[1]]),
				Source:   c.Name(),
			})
		}
	}
	return out
}
