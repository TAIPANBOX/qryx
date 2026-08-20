package detectors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// Default() had never been run by a test, and what it decides is which
// detectors exist as far as `qryx scan` is concerned.
//
// The failure this guards is not a crash. A detector gets written, gets its
// own unit tests, goes green, and is never added here. Nothing is red, the
// file is present, its tests pass, and it never sees a single file of anybody's
// code. It reads as coverage from every angle except the only one that matters.

// Every exported New* constructor in this package is in the default set.
//
// Parsed out of the package's own source rather than listed here, because a
// hand-kept list is the same problem one level up: it would need editing by
// the same person who forgot to edit Default().
func TestEveryDetectorInThisPackageIsInTheDefaultSet(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing this package: %v", err)
	}
	pkg, ok := pkgs["detectors"]
	if !ok {
		t.Fatal("the detectors package did not parse, so this measured nothing")
	}

	var constructors []string
	for _, f := range pkg.Files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "New") {
				continue
			}
			if fn.Name.Name == "New" {
				continue
			}
			constructors = append(constructors, fn.Name.Name)
		}
	}
	if len(constructors) == 0 {
		t.Fatal("no New* constructor found in this package, so this measured " +
			"nothing. An absent subject is not agreement.")
	}

	inDefault := map[string]bool{}
	for _, d := range Default() {
		inDefault[strings.ToLower(d.Name())] = true
	}

	var missing []string
	for _, c := range constructors {
		// NewCertFile -> certfile, matched against the detector's own Name().
		if !inDefault[strings.ToLower(strings.TrimPrefix(c, "New"))] {
			missing = append(missing, c)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%v exist in this package and are not in Default(). "+
			"A detector nobody registers never sees a single file: its own "+
			"tests pass, nothing is red, and it reads as coverage.", missing)
	}
}

// Two detectors under one name would make findings unattributable, and a
// duplicate in the slice would run one detector twice over every file.
func TestTheDefaultSetHasNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Default() {
		if seen[d.Name()] {
			t.Fatalf("%q appears twice in Default(): every file would be "+
				"scanned by it twice and every finding reported twice", d.Name())
		}
		seen[d.Name()] = true
	}
	if len(seen) == 0 {
		t.Fatal("Default() is empty: qryx scan would report a clean tree for " +
			"any input at all, which is the most convincing wrong answer it " +
			"could give")
	}
}

// A detector with no name cannot be attributed, filtered or suppressed, and
// its findings would all merge under the empty string in any report grouped by
// source.
func TestEveryDefaultDetectorNamesItself(t *testing.T) {
	for i, d := range Default() {
		if strings.TrimSpace(d.Name()) == "" {
			t.Fatalf("the detector at index %d has no name", i)
		}
	}
}
