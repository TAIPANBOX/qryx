package scan

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// Test code is scanned, reported, and kept out of the production numbers.
//
// It is scanned because a hardcoded key in a test file is still a hardcoded key
// on disk, and test fixtures do leak. It is kept separate because a compliance
// figure that counts fixtures as production cryptography is wrong in the
// direction that matters: it inflates the inventory, and it buries the findings
// an operator actually has to migrate under ones nobody ships.
//
// Measured on five repositories of this stack, more than half of every
// cryptographic occurrence found was in test code, and over half the assets
// existed ONLY in test code. Those are not small corrections to the number.
//
// The rules below are deliberately conservative. A path is test code only when
// it says so by a convention the language itself established, so a false
// positive would take a deliberately misleading filename. When in doubt a file
// counts as production, because the cost of the two mistakes is not symmetric:
// calling production code "test" hides real crypto debt, while calling test
// code "production" only inflates a number that is already reported separately.

// testDirs are directory names that mark everything below them as test code.
// `examples` is deliberately NOT here: example code is shipped, read and copied
// by users, so its cryptography is as real as any other.
var testDirs = map[string]bool{
	"test":      true,
	"tests":     true,
	"testdata":  true,
	"__tests__": true,
	"spec":      true,
	"specs":     true,
	"fixture":   true,
	"fixtures":  true,
}

// testFileSuffixes mark a single file as test code regardless of its directory.
var testFileSuffixes = []string{
	"_test.go",  // go
	"_test.py",  // python (pytest, both conventions)
	"_test.rs",  // rust
	"_test.exs", // elixir
	"_spec.rb",  // ruby
	".test.ts", ".test.tsx", ".test.js", ".test.jsx", ".test.mjs",
	".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx", ".spec.mjs",
	"Test.java", "Tests.java", "TestCase.java",
}

// testFileNames are exact filenames that only ever exist to support tests.
var testFileNames = map[string]bool{
	"conftest.py": true,
}

// PartitionTests splits findings into production and test code, preserving the
// order within each half.
//
// This is the single point where the two are separated, applied once to the
// whole result before anything consumes it, so the snapshot written by --save,
// the events emitted by --events, the policy gate, the compliance verdict and
// every --format all agree on what "production" means. Splitting per reporter
// instead would let them disagree, which is how a dashboard ends up
// contradicting the CI gate that feeds it.
func PartitionTests(findings []model.Finding) (production, test []model.Finding) {
	for _, f := range findings {
		if f.Location.IsTest {
			test = append(test, f)
		} else {
			production = append(production, f)
		}
	}
	return production, test
}

// rustTestLines reports which 1-based line numbers of a Rust source file fall
// inside a `#[cfg(test)]` region.
//
// Rust is the one language in this stack whose tests usually do NOT live in a
// separate file: the idiom is an inline `#[cfg(test)] mod tests { ... }` at the
// bottom of the production `.rs`. Path rules alone therefore miss them, and on
// this stack's own Rust that is not academic: scanning tokenfuse, the single
// "critical: private key material embedded in source" finding was the literal
// `-----BEGIN EC PRIVATE KEY-----\nnope\n-----END EC PRIVATE KEY-----` inside
// `#[test] fn garbage_key_material_is_none` asserting the parser rejects
// garbage, i.e. the one thing an operator would scramble to fix was a test.
//
// This is a heuristic, not a Rust parser, and it is deliberately biased the
// safe way. It only recognises the `#[cfg(test)]` / `#![cfg(test)]` idiom, and
// it counts braces on lines with `//` comments and string contents stripped
// first, so a stray brace in a string cannot silently drag the region across
// real production code. The asymmetry from IsTestPath's own doc still governs:
// under-detecting a test region only re-inflates a separately-reported number,
// while over-detecting would hide real debt, so when unsure this stays out.
func rustTestLines(content []byte) map[int]bool {
	lines := strings.Split(string(content), "\n")
	test := make(map[int]bool)

	inRegion := false // inside a brace-delimited #[cfg(test)] mod/block
	armed := false    // saw #[cfg(test)], still waiting for its opening brace
	depth := 0

	for i, raw := range lines {
		lineNo := i + 1
		code := stripRustNoise(raw)

		// `#![cfg(test)]` is an inner attribute: the whole enclosing module is
		// test-only, so from here down is test.
		if strings.Contains(code, "#![cfg(test)]") {
			for j := lineNo; j <= len(lines); j++ {
				test[j] = true
			}
			return test
		}

		if inRegion {
			test[lineNo] = true
			depth += strings.Count(code, "{") - strings.Count(code, "}")
			if depth <= 0 {
				inRegion = false
			}
			continue
		}

		if !armed && strings.Contains(code, "#[cfg(test)]") {
			armed = true
		}
		if armed {
			test[lineNo] = true
			if opens := strings.Count(code, "{"); opens > 0 {
				depth = opens - strings.Count(code, "}")
				armed = false
				inRegion = depth > 0
			}
		}
	}
	return test
}

// stripRustNoise blanks `//` line comments and double-quoted string contents so
// that brace counting in rustTestLines is not thrown off by braces that live in
// a comment or a string literal. Not a full lexer (it does not track block
// comments, raw strings or char literals), which is acceptable: its only job is
// to keep the brace tally honest, and the cases it misses are rare around a
// test module and fail toward under-detection.
func stripRustNoise(line string) string {
	var b strings.Builder
	inStr := false
	for j := 0; j < len(line); j++ {
		c := line[j]
		if !inStr && c == '/' && j+1 < len(line) && line[j+1] == '/' {
			break // rest of the line is a comment
		}
		if c == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// IsTestPath reports whether rel (a path relative to the scan root, using the
// OS separator) is test code by the conventions above.
func IsTestPath(rel string) bool {
	rel = filepath.ToSlash(rel)
	dir, name := path.Split(rel)

	for _, seg := range strings.Split(strings.Trim(dir, "/"), "/") {
		if testDirs[strings.ToLower(seg)] {
			return true
		}
	}
	if testFileNames[name] {
		return true
	}
	if strings.HasPrefix(name, "test_") && strings.HasSuffix(name, ".py") {
		return true
	}
	for _, suffix := range testFileSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
