package scan_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
	"github.com/TAIPANBOX/qryx/internal/scan/detectors"
)

func TestScanSample(t *testing.T) {
	s := scan.New(
		detectors.NewCertFile(),
		detectors.NewGoAST(),
		detectors.NewCryptoCall(),
		detectors.NewTLSConfig(),
		detectors.NewHardcoded(),
		detectors.NewDeps(),
	)
	res, err := s.Scan("../../testdata/sample")
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]model.RiskClass{}
	for _, f := range res.Findings {
		found[f.Asset.Algorithm] = f.Risk.Class
	}

	want := map[string]model.RiskClass{
		"MD5": model.RiskWeak,
		// RSA-1024: the AST detector extracts the 1024-bit key size, so this is
		// classified weak (below 2048) rather than generic quantum-vulnerable.
		"RSA":         model.RiskWeak,
		"SHA-1":       model.RiskWeak,
		"SHA-256":     model.RiskNone,
		"private-key": model.RiskHardcoded,
	}
	for algo, wantClass := range want {
		got, ok := found[algo]
		if !ok {
			t.Errorf("expected to find %s, did not", algo)
			continue
		}
		if got != wantClass {
			t.Errorf("%s risk = %q, want %q", algo, got, wantClass)
		}
	}
}

// The walker is the single place that knows which file a finding came from, so
// it is the single place that can stamp the test/production split. This proves
// the stamp survives all the way out of a real scan of a real tree, rather than
// only that the path classifier agrees with itself.
func TestScanStampsTestCode(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The same weak call in both halves of the tree, so any difference in the
	// result is the stamp and nothing else.
	const src = "package p\n\nimport \"crypto/md5\"\n\nfunc f() { _ = md5.New() }\n"
	write("prod.go", src)
	write("prod_test.go", src)
	write("testdata/fixture.go", src)

	res, err := scan.New(detectors.NewGoAST(), detectors.NewCryptoCall()).Scan(dir)
	if err != nil {
		t.Fatal(err)
	}

	byFile := map[string]bool{}
	for _, f := range res.Findings {
		byFile[filepath.ToSlash(f.Location.File)] = f.Location.IsTest
	}
	for file, wantTest := range map[string]bool{
		"prod.go":             false,
		"prod_test.go":        true,
		"testdata/fixture.go": true,
	} {
		got, ok := byFile[file]
		if !ok {
			t.Errorf("no finding for %s; got %v", file, byFile)
			continue
		}
		if got != wantTest {
			t.Errorf("%s: IsTest = %v, want %v", file, got, wantTest)
		}
	}

	prod, test := scan.PartitionTests(res.Findings)
	if len(prod) == 0 || len(test) == 0 {
		t.Fatalf("expected both halves non-empty, got %d production / %d test", len(prod), len(test))
	}
	for _, f := range prod {
		if f.Location.IsTest {
			t.Errorf("test finding leaked into the production half: %s", f.Location.File)
		}
	}
}
