package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The NCSC report's 2031 milestone counts how many highest-priority assets
// were migrated. Until 2026-11-23 that count was the literal 0 on every run, in
// both the JSON and the HTML page, and read exactly like a measurement: "0
// migrated" is what a team that has done nothing would see, and also what a
// team that has replaced every exposed key would see. These tests hold the
// replacement: a count measured from the --baseline the drift gate already
// reads, and an explicit "not measured" whenever there is no like-for-like
// baseline to measure against.

// ecdhSource is a Go file whose crypto/ecdh import the goast detector reports
// as a quantum-vulnerable key exchange: long-lived data, so it is in the 2031
// highest-priority subset.
const ecdhSource = "package p\n\nimport \"crypto/ecdh\"\n\nvar _ = ecdh.X25519\n"

// plainSource holds no cryptography, so a tree holding only it inventories
// nothing quantum-vulnerable.
const plainSource = "package p\n\nvar X = 1\n"

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// saveBaseline runs a real scan of dir with --save, so the baseline is exactly
// what an operator's CI would have stored, not a hand-built approximation.
func saveBaseline(t *testing.T, dir string) string {
	t.Helper()
	snap := filepath.Join(t.TempDir(), "baseline.json")
	var err error
	captureOutput(t, func() {
		err = run([]string{"scan", "--format", "cbom", "--save", snap, dir})
	})
	if err != nil {
		t.Fatalf("scan --save: %v", err)
	}
	return snap
}

// priority2031 runs `scan --format ncsc` with the given extra flags and
// returns the highestPriority2031 object as generic JSON, so the test reads
// the document a consumer reads rather than a Go struct that could drift from
// it.
func priority2031(t *testing.T, dir string, flags ...string) map[string]any {
	t.Helper()
	args := append([]string{"scan", "--format", "ncsc"}, flags...)
	args = append(args, dir)
	var (
		out string
		err error
	)
	out, _ = captureOutput(t, func() { err = run(args) })
	if err != nil {
		t.Fatalf("run(%v): %v", args, err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("ncsc output is not JSON: %v\n%s", err, out)
	}
	p, ok := doc["highestPriority2031"].(map[string]any)
	if !ok {
		t.Fatalf("no highestPriority2031 object in:\n%s", out)
	}
	return p
}

// requireMeasured asserts the count was measured and equals want.
func requireMeasured(t *testing.T, p map[string]any, want int) {
	t.Helper()
	if m, _ := p["migratedMeasured"].(bool); !m {
		t.Fatalf("migratedMeasured = %v, want true (basis: %v)", p["migratedMeasured"], p["migratedBasis"])
	}
	got, ok := p["migratedCount"].(float64)
	if !ok {
		t.Fatalf("migratedCount = %#v, want the number %d", p["migratedCount"], want)
	}
	if int(got) != want {
		t.Errorf("migratedCount = %v, want %d (basis: %v)", got, want, p["migratedBasis"])
	}
}

// requireNotMeasured asserts the count is absent (JSON null), flagged as not
// measured, and that the basis says why in words containing reason.
func requireNotMeasured(t *testing.T, p map[string]any, reason string) {
	t.Helper()
	v, present := p["migratedCount"]
	if !present || v != nil {
		t.Errorf("migratedCount = %#v (present %v), want an explicit null: a 0 here reads as a measured zero", v, present)
	}
	if m, ok := p["migratedMeasured"].(bool); !ok || m {
		t.Errorf("migratedMeasured = %#v, want false", p["migratedMeasured"])
	}
	basis, _ := p["migratedBasis"].(string)
	if !strings.Contains(basis, "not measured") || !strings.Contains(basis, reason) {
		t.Errorf("migratedBasis = %q, want it to say \"not measured\" and %q", basis, reason)
	}
}

func TestNCSCMigratedCountsAHighestPriorityAssetGoneSinceTheBaseline(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kex.go"), ecdhSource)
	base := saveBaseline(t, dir)

	// The key exchange is replaced: the file no longer imports crypto/ecdh.
	writeFile(t, filepath.Join(dir, "kex.go"), plainSource)

	p := priority2031(t, dir, "--baseline", base)
	requireMeasured(t, p, 1)
	if got, _ := p["count"].(float64); got != 0 {
		t.Errorf("count = %v, want 0: nothing highest-priority is left", got)
	}
	mf, _ := p["migratedFindings"].([]any)
	if len(mf) != 1 {
		t.Fatalf("migratedFindings = %#v, want the one asset that left", p["migratedFindings"])
	}
	if alg, _ := mf[0].(map[string]any)["algorithm"].(string); alg != "ECDH" {
		t.Errorf("migrated finding algorithm = %q, want ECDH", alg)
	}
}

func TestNCSCMigratedDoesNotCountANewAsset(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "plain.go"), plainSource)
	base := saveBaseline(t, dir)

	// A key exchange arrives after the baseline: new work, not migrated work.
	writeFile(t, filepath.Join(dir, "kex.go"), ecdhSource)

	p := priority2031(t, dir, "--baseline", base)
	requireMeasured(t, p, 0)
	if got, _ := p["count"].(float64); got != 1 {
		t.Errorf("count = %v, want 1: the new asset is outstanding", got)
	}
	if got, _ := p["remainingCount"].(float64); got != 1 {
		t.Errorf("remainingCount = %v, want 1", got)
	}
}

// @decided 2026-11-23: an asset is matched across scans by the same identity
// the drift diff uses (type, algorithm, key size, risk class), never by its
// location, so a key exchange that only moved to another file is still in the
// estate and is not migrated.
func TestNCSCMigratedDoesNotCountAnAssetThatOnlyMovedFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kex.go"), ecdhSource)
	base := saveBaseline(t, dir)

	if err := os.Remove(filepath.Join(dir, "kex.go")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "sub", "moved.go"), ecdhSource)

	p := priority2031(t, dir, "--baseline", base)
	requireMeasured(t, p, 0)
	if got, _ := p["count"].(float64); got != 1 {
		t.Errorf("count = %v, want 1: the moved asset is still outstanding", got)
	}
}

func TestNCSCMigratedIsNotMeasuredWithoutABaseline(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kex.go"), ecdhSource)
	p := priority2031(t, dir)
	requireNotMeasured(t, p, "no --baseline")
	// Remaining is still a real figure: it is this scan's own count.
	if got, _ := p["remainingCount"].(float64); got != 1 {
		t.Errorf("remainingCount = %v, want 1", got)
	}
}

func TestNCSCMigratedIsNotMeasuredWhenTheBaselineIsMissing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kex.go"), ecdhSource)
	missing := filepath.Join(t.TempDir(), "no-such-baseline.json")
	p := priority2031(t, dir, "--baseline", missing)
	requireNotMeasured(t, p, "not found")
}

// An empty baseline of the same target is a real measurement: there was
// nothing highest-priority to migrate, so the zero is earned.
func TestNCSCMigratedFromAnEmptyBaselineIsAMeasuredZero(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kex.go"), ecdhSource)
	base := filepath.Join(t.TempDir(), "empty.json")
	body, _ := json.Marshal(map[string]any{"schemaVersion": 1, "root": dir, "assets": []any{}})
	writeFile(t, base, string(body))

	p := priority2031(t, dir, "--baseline", base)
	requireMeasured(t, p, 0)
}

// A baseline of another target would turn "different things were scanned"
// into "things were migrated", so the count is refused, not computed.
func TestNCSCMigratedIsNotMeasuredAgainstABaselineOfAnotherTarget(t *testing.T) {
	other := t.TempDir()
	writeFile(t, filepath.Join(other, "kex.go"), ecdhSource)
	base := saveBaseline(t, other)

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "plain.go"), plainSource)
	p := priority2031(t, dir, "--baseline", base)
	requireNotMeasured(t, p, "another target")
}

func TestNCSCMigratedRefusesAHostileBaseline(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "plain.go"), plainSource)

	// Files that are not a snapshot at all are an error, exactly as the drift
	// gate already treats them: no report is written with a guessed figure.
	unreadable := map[string]string{
		"truncated JSON":    `{"schemaVersion":1,"assets":[{`,
		"a JSON array":      `[]`,
		"a JSON string":     `"baseline"`,
		"binary garbage":    "\x00\xff\xfe not json",
		"assets not a list": `{"schemaVersion":1,"assets":"many"}`,
	}
	for name, body := range unreadable {
		t.Run(name, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "bad.json")
			writeFile(t, base, body)
			var err error
			out, _ := captureOutput(t, func() {
				err = run([]string{"scan", "--format", "ncsc", "--baseline", base, dir})
			})
			if err == nil {
				t.Fatalf("a baseline holding %s was accepted and produced:\n%s", name, out)
			}
			if !strings.Contains(err.Error(), "baseline") {
				t.Errorf("error %q does not say the baseline was the problem", err)
			}
		})
	}

	// A file that parses but is not this version's snapshot is not an error
	// for a report that only reads it, but nothing is measured from it.
	t.Run("a schema version this build does not write", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "future.json")
		body, _ := json.Marshal(map[string]any{"schemaVersion": 99, "root": dir, "assets": []any{}})
		writeFile(t, base, string(body))
		p := priority2031(t, dir, "--baseline", base)
		requireNotMeasured(t, p, "schemaVersion 99")
	})

	// The same asset listed twice in a hand-edited baseline is one asset.
	t.Run("one asset listed twice", func(t *testing.T) {
		node := map[string]any{
			"Asset": map[string]any{"Type": "algorithm", "Algorithm": "ECDH", "Primitive": "key-exchange"},
			"Risk":  map[string]any{"Class": "quantum-vulnerable", "Severity": 3},
			"Occurrences": []any{map[string]any{
				"Location": map[string]any{"File": "kex.go", "Line": 3}, "Primitive": "key-exchange", "Source": "goast",
			}},
		}
		base := filepath.Join(t.TempDir(), "twice.json")
		body, _ := json.Marshal(map[string]any{"schemaVersion": 1, "root": dir, "assets": []any{node, node}})
		writeFile(t, base, string(body))
		p := priority2031(t, dir, "--baseline", base)
		requireMeasured(t, p, 1)
	})
}

// The HTML page must not print "0 migrated" when nothing was measured.
func TestNCSCHTMLSaysMigratedIsNotMeasuredWithoutABaseline(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kex.go"), ecdhSource)
	var err error
	out, _ := captureOutput(t, func() {
		err = run([]string{"scan", "--format", "ncsc-html", dir})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "0 migrated") {
		t.Error("the page prints \"0 migrated\" with no baseline: an unmeasured figure reads as a measured zero")
	}
	if !strings.Contains(out, "migrated: not measured") {
		t.Error("the page does not say the migrated count was not measured")
	}
}

// With a baseline, the page carries the measured number.
func TestNCSCHTMLShowsTheMeasuredMigratedCount(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kex.go"), ecdhSource)
	base := saveBaseline(t, dir)
	writeFile(t, filepath.Join(dir, "kex.go"), plainSource)
	var err error
	out, _ := captureOutput(t, func() {
		err = run([]string{"scan", "--format", "ncsc-html", "--baseline", base, dir})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1 migrated since the baseline") {
		t.Error("the page does not show the one asset migrated since the baseline")
	}
}
