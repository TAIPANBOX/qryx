package scan

import (
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

func TestIsTestPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
		why  string
	}{
		// Directory conventions.
		{"internal/scan/testdata/key.pem", true, "testdata tree"},
		{"tests/oidc.rs", true, "tests dir"},
		{"crates/cloud/tests/oidc.rs", true, "nested tests dir"},
		{"test/helper.py", true, "singular test dir"},
		{"src/__tests__/crypto.ts", true, "jest convention"},
		{"spec/models/key_spec.rb", true, "spec dir"},
		{"fixtures/expired.pem", true, "fixtures dir"},
		{"TestData/key.pem", true, "case-insensitive directory match"},

		// File conventions.
		{"internal/scan/walker_test.go", true, "go test file"},
		{"verdryx/store_test.py", true, "python suffix convention"},
		{"verdryx/test_store.py", true, "python prefix convention"},
		{"src/lib_test.rs", true, "rust test file"},
		{"web/crypto.test.ts", true, "ts test file"},
		{"web/crypto.spec.js", true, "js spec file"},
		{"conftest.py", true, "pytest conftest"},
		{"src/main/java/KeyTest.java", true, "java test class"},

		// Production. These are the ones that must never be misfiled: calling
		// production code "test" would hide real crypto debt.
		{"crates/cloud/src/audit_sign.rs", false, "ordinary source file"},
		{"internal/scan/walker.go", false, "ordinary go file"},
		{"cmd/qryx/main.go", false, "entrypoint"},
		{"examples/sign.go", false, "example code is shipped and copied, so it is production"},
		{"src/protest/handler.go", false, "a directory merely containing 'test' as a substring"},
		{"internal/latest/config.go", false, "'latest' must not match 'test'"},
		{"src/contest.py", false, "'contest.py' is not 'conftest.py'"},
		{"pkg/attestation/verify.go", false, "'attestation' contains 'test' as a substring"},
		{"", false, "empty path"},
	}
	for _, c := range cases {
		if got := IsTestPath(filepath.FromSlash(c.path)); got != c.want {
			t.Errorf("IsTestPath(%q) = %v, want %v (%s)", c.path, got, c.want, c.why)
		}
	}
}

func TestPartitionTests(t *testing.T) {
	f := func(file string, isTest bool) model.Finding {
		return model.Finding{Location: model.Location{File: file, IsTest: isTest}}
	}
	in := []model.Finding{
		f("src/a.go", false),
		f("src/a_test.go", true),
		f("src/b.go", false),
		f("testdata/k.pem", true),
	}
	prod, test := PartitionTests(in)
	if len(prod) != 2 || len(test) != 2 {
		t.Fatalf("split = %d production / %d test, want 2/2", len(prod), len(test))
	}
	// Order within each half is preserved, so a reader of either list sees the
	// same sequence the scan produced.
	if prod[0].Location.File != "src/a.go" || prod[1].Location.File != "src/b.go" {
		t.Errorf("production order not preserved: %+v", prod)
	}
	if test[0].Location.File != "src/a_test.go" || test[1].Location.File != "testdata/k.pem" {
		t.Errorf("test order not preserved: %+v", test)
	}
}

func TestPartitionTestsWithNothingToSplit(t *testing.T) {
	prod, test := PartitionTests(nil)
	if prod != nil || test != nil {
		t.Errorf("empty input must produce two empty halves, got %v / %v", prod, test)
	}
}
