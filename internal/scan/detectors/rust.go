package detectors

import (
	"path/filepath"
	"regexp"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// Rust finds cryptographic primitives in Rust source.
//
// # Why this is its own detector
//
// It was missing, and the absence was invisible: `cryptocall` carries patterns for
// Python and JS/TS, Go has its AST detector, and a Rust codebase therefore scanned
// clean because nothing looked at it. A scan of a 169-file Rust project that
// implements ECDSA P-384 by hand reported one ECDSA finding, in a Python file used
// to generate test vectors, and `--policy cnsa` passed. A pass from not looking is
// worse than no scan at all, because somebody files it as evidence.
//
// # Why regex, and how the false positives are avoided
//
// The Go detector uses the AST specifically because regex matches comments and string
// literals. Rust has no stdlib AST here and pulling a parser in would cost more than
// this is worth, so the text is stripped of comments and string literals first and
// the patterns then match **identifiers rather than prose**: `Sha256`, `ECDSA_P384`,
// `p384::`, `MlKem768`. A file whose doc comment explains that ECDSA is
// quantum-vulnerable is not a file that uses ECDSA, and a detector that cannot tell
// the difference produces a report nobody reads twice.
type Rust struct {
	patterns []pattern
}

func NewRust() *Rust {
	mk := func(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }
	return &Rust{patterns: []pattern{
		// Signature and key exchange. The constant forms are what `ring` and
		// `aws-lc-rs` expose; the `::` forms are the RustCrypto crates; the
		// CamelCase forms catch a hand-written implementation naming its own type,
		// which is how the codebase that prompted this file does it.
		{mk(`\bECDSA_P(?:256|384|521)\b|\bEcdsa[A-Z][A-Za-z0-9]*|\bp(?:256|384|521)::|\buse\s+p(?:256|384|521)\b`), "ECDSA", model.PrimitiveSignature},
		{mk(`\bEd25519[A-Za-z0-9]*|\bed25519::|\bED25519\b`), "Ed25519", model.PrimitiveSignature},
		{mk(`\bRsa[A-Z][A-Za-z0-9]*|\brsa::|\bRSA_PKCS1[A-Z0-9_]*|\bRSA_PSS[A-Z0-9_]*`), "RSA", model.PrimitiveSignature},
		{mk(`\bX25519[A-Za-z0-9]*|\bx25519::`), "ECDH", model.PrimitiveKeyExch},

		// Post-quantum, so a codebase that has already migrated is credited rather
		// than merely not flagged.
		{mk(`\bMlKem[A-Za-z0-9]*|\bML_KEM[A-Z0-9_]*|\bml_kem::`), "ML-KEM", model.PrimitiveKeyExch},
		{mk(`\bMlDsa[A-Za-z0-9]*|\bML_DSA[A-Z0-9_]*|\bml_dsa::`), "ML-DSA", model.PrimitiveSignature},
		{mk(`\bSlhDsa[A-Za-z0-9]*|\bSLH_DSA[A-Z0-9_]*`), "SLH-DSA", model.PrimitiveSignature},

		// Hashes.
		{mk(`\bSha3_[0-9]+|\bsha3::`), "SHA3", model.PrimitiveHash},
		{mk(`\bSha512\b|\bSHA512\b`), "SHA-512", model.PrimitiveHash},
		{mk(`\bSha384\b|\bSHA384\b`), "SHA-384", model.PrimitiveHash},
		{mk(`\bSha256\b|\bSHA256\b`), "SHA-256", model.PrimitiveHash},
		{mk(`\bSha1\b|\bsha1::|\bSHA1\b`), "SHA-1", model.PrimitiveHash},
		{mk(`\bMd5\b|\bmd5::|\bMD5\b`), "MD5", model.PrimitiveHash},

		// Symmetric.
		{mk(`\bAes[0-9]*[A-Z][A-Za-z0-9]*|\bAES_[0-9]+_[A-Z]+\b|\baes_gcm::|\baes::`), "AES", model.PrimitiveEncryption},
		{mk(`\bChaCha20[A-Za-z0-9]*|\bCHACHA20[A-Z0-9_]*|\bchacha20`), "ChaCha20", model.PrimitiveEncryption},
		{mk(`\bDes\b|\bDES\b|\bTripleDes\b`), "DES", model.PrimitiveEncryption},
		{mk(`\bRc4\b|\bRC4\b`), "RC4", model.PrimitiveEncryption},

		// Keyed hashing, reported so the graph is complete rather than because it
		// carries risk.
		{mk(`\bHmac[A-Z][A-Za-z0-9]*|\bhmac_sha[0-9]+|\bhmac::`), "HMAC", model.PrimitiveHash},
	}}
}

func (r *Rust) Name() string { return "rust" }

func (r *Rust) Wants(path string) bool { return filepath.Ext(path) == ".rs" }

func (r *Rust) Detect(f scan.File) []model.Finding {
	code := stripRustNonCode(f.Content)
	var out []model.Finding
	for _, p := range r.patterns {
		loc := p.re.FindIndex(code)
		if loc == nil {
			continue
		}
		out = append(out, model.Finding{
			Asset: model.Asset{
				Type:      model.TypeAlgorithm,
				Algorithm: p.algorithm,
				Primitive: p.primitive,
			},
			Location: model.Location{File: f.Path, Line: lineNumber(code, loc[0])},
			Evidence: string(code[loc[0]:loc[1]]),
			Source:   r.Name(),
		})
	}
	return out
}

// stripRustNonCode blanks comments and string literals, keeping every byte's
// position so a reported line number still points at the right line.
//
// Blanking rather than deleting is the whole trick: a detector that removed the
// bytes would report a line number from a file that no longer exists, and the reader
// would be sent to the wrong place with total confidence.
func stripRustNonCode(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)

	const (
		code = iota
		lineComment
		blockComment
		str
		raw
		char
	)
	state := code
	depth := 0  // nested /* */, which Rust allows and C does not
	hashes := 0 // r##"..."## needs the same number of hashes to close
	seen := 0   // hashes seen while looking for the end of a raw string
	blank := func(i int) {
		if out[i] != '\n' {
			out[i] = ' '
		}
	}

	for i := 0; i < len(src); i++ {
		switch state {
		case code:
			switch {
			case src[i] == '/' && i+1 < len(src) && src[i+1] == '/':
				state, out[i] = lineComment, ' '
			case src[i] == '/' && i+1 < len(src) && src[i+1] == '*':
				// Both bytes consumed on entry. Leaving the `*` for the next
				// iteration made the opening delimiter itself look like a nested
				// one, so `depth` reached 2, `*/` brought it back to 1, and the
				// comment never closed: everything after the first block comment
				// in a file was invisible. The test that caught it asks only for a
				// line number, which is why it was worth writing.
				state, depth = blockComment, 1
				blank(i)
				blank(i + 1)
				i++
			case src[i] == '"':
				state = str
				blank(i)
			case src[i] == '\'':
				// A lifetime (`'a`) is not a character literal, and telling them
				// apart matters: treating `'a` as an unterminated literal would
				// blank the rest of the file and hide everything in it.
				if i+2 < len(src) && (src[i+2] == '\'' || src[i+1] == '\\') {
					state = char
					blank(i)
				}
			case src[i] == 'r' && i+1 < len(src) && (src[i+1] == '"' || src[i+1] == '#'):
				j := i + 1
				for j < len(src) && src[j] == '#' {
					j++
				}
				if j < len(src) && src[j] == '"' {
					state, hashes, seen = raw, j-i-1, 0
					for k := i; k <= j; k++ {
						blank(k)
					}
					i = j
				}
			}
		case lineComment:
			if src[i] == '\n' {
				state = code
			} else {
				blank(i)
			}
		case blockComment:
			blank(i)
			if src[i] == '/' && i > 0 && src[i-1] == '*' && depth > 0 {
				depth--
				if depth == 0 {
					state = code
				}
			} else if src[i] == '*' && i > 0 && src[i-1] == '/' {
				depth++
			}
		case str:
			blank(i)
			if src[i] == '\\' {
				if i+1 < len(src) {
					blank(i + 1)
					i++
				}
			} else if src[i] == '"' {
				state = code
			}
		case char:
			blank(i)
			if src[i] == '\'' {
				state = code
			}
		case raw:
			blank(i)
			if src[i] == '"' {
				seen = 0
				for j := i + 1; j < len(src) && src[j] == '#'; j++ {
					seen++
				}
				if seen >= hashes {
					for k := i + 1; k <= i+hashes; k++ {
						blank(k)
					}
					i += hashes
					state = code
				}
			}
		}
	}
	return out
}
