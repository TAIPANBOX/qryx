package agility

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/scan/detectors"
)

// The two tests in this file exist because sourceAgility is a second list of
// every finding source in the tree, kept by hand, and a hand-kept second list
// drifts from the first one in silence. It did: the Terraform detector shipped
// with no entry here, so every key declared in HCL scored `low` ("code change
// + redeploy") and its effort note named no source at all. Nothing was red.
//
// The sources arrive by two routes, so there are two gates. A detector in the
// scan tree announces itself through Name(), and detectors.Default() can be
// walked directly. A connector (the cloud clients, the TLS prober, binscan,
// agentstack) stamps a string literal on the findings it builds, and the only
// place that list exists is the source, so the second gate reads it out of the
// source.

// TestEveryDefaultDetectorHasAnAgilityLevel walks the detector registry qryx
// actually scans with. This is the gate that was missing: adding
// NewTerraform() to Default() should not have been able to go green without an
// entry here.
func TestEveryDefaultDetectorHasAnAgilityLevel(t *testing.T) {
	for _, d := range detectors.Default() {
		if _, ok := sourceAgility[d.Name()]; !ok {
			t.Errorf("detector %q is in detectors.Default() with no sourceAgility entry: every asset it finds falls through to the %q fallback and its name never reaches the effort note", d.Name(), Low)
		}
	}
}

// TestEveryFindingSourceLiteralHasAnAgilityLevel reads every `Source: "..."`
// literal out of a model.Finding composite literal in the tree, which is how
// the connectors name themselves, and requires each to be ranked.
func TestEveryFindingSourceLiteralHasAnAgilityLevel(t *testing.T) {
	root := moduleRoot(t)
	found := findingSourceLiterals(t, root)

	if len(found) == 0 {
		t.Fatal(`no Source: "..." literals found under the module root: the walk is looking at the wrong tree, and a gate that goes green because it found nothing to check is worse than no gate`)
	}

	srcs := make([]string, 0, len(found))
	for s := range found {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs) // map order is not an order (invariant 8)

	for _, s := range srcs {
		if _, ok := sourceAgility[s]; !ok {
			t.Errorf("source %q is stamped on findings in %s but has no sourceAgility entry: its assets fall through to the %q fallback", s, strings.Join(found[s], ", "), Low)
		}
	}
}

// moduleRoot walks up from the test's working directory to the directory
// holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory: cannot find the tree to walk")
		}
		dir = parent
	}
}

// findingSourceLiterals maps each string literal assigned to a Source field of
// a model.Finding to the files it appears in. Test files are skipped: they
// carry deliberately unknown sources to exercise the fallback.
func findingSourceLiterals(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (name == "testdata" || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, s := range sourcesIn(f) {
			if files := out[s]; len(files) == 0 || files[len(files)-1] != rel {
				out[s] = append(out[s], rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// sourcesIn returns the Source string literals of every model.Finding literal
// in f, in both the shapes the connectors use: model.Finding{...} and the
// untyped elements of []model.Finding{{...}}.
func sourcesIn(f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		switch {
		case isFindingType(lit.Type):
			out = append(out, sourceField(lit)...)
		case isFindingSliceType(lit.Type):
			for _, el := range lit.Elts {
				if inner, ok := el.(*ast.CompositeLit); ok && inner.Type == nil {
					out = append(out, sourceField(inner)...)
				}
			}
		}
		return true
	})
	return out
}

func isFindingType(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == "Finding"
}

func isFindingSliceType(e ast.Expr) bool {
	arr, ok := e.(*ast.ArrayType)
	return ok && isFindingType(arr.Elt)
}

// sourceField returns the string literals given to the Source field of one
// composite literal. A non-literal value (t.Name(), a const) names no source
// this test can read, and is left to the detector-registry gate above.
func sourceField(lit *ast.CompositeLit) []string {
	var out []string
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Source" {
			continue
		}
		bl, ok := kv.Value.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			continue
		}
		if s, err := strconv.Unquote(bl.Value); err == nil && s != "" {
			out = append(out, s)
		}
	}
	return out
}
