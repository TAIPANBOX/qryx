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
