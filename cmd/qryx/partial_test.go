package main

import (
	"bytes"
	"strings"
	"testing"

	gcpcloud "github.com/TAIPANBOX/qryx/internal/cloud/gcp"
)

// A cloud inventory that skipped resources it could not read looks exactly
// like a complete one on stdout: the same JSON, the same asset table, the
// same exit 0. This line is the only difference, so it has to be there and it
// has to use the word.
func TestPartialInventoryIsReportedAsPartial(t *testing.T) {
	var buf bytes.Buffer
	reportPartialInventory(&buf, "azure", []string{
		"key vault key https://v.azure.net/keys/a/1: Forbidden: no keys/get",
	})
	out := buf.String()
	if !strings.Contains(out, "partial") {
		t.Errorf("stderr %q never says the inventory is partial", out)
	}
	if !strings.Contains(out, "keys/a/1") {
		t.Errorf("stderr %q does not name the resource it could not read", out)
	}
	if !strings.Contains(out, "1 resource(s)") {
		t.Errorf("stderr %q does not count what is missing", out)
	}
}

// The count stays exact when the list is sampled: an operator who reads "3
// resource(s)" from a run that skipped 30 has been told something false, which
// is worse than the long line the cap exists to avoid.
func TestPartialInventoryCountsEverythingItDoesNotName(t *testing.T) {
	var skipped []string
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		skipped = append(skipped, "kms key "+id+": AccessDenied")
	}
	var buf bytes.Buffer
	reportPartialInventory(&buf, "aws", skipped)
	out := buf.String()
	if !strings.Contains(out, "5 resource(s)") {
		t.Errorf("stderr %q does not report all 5 skipped resources", out)
	}
	if !strings.Contains(out, "and 2 more") {
		t.Errorf("stderr %q does not say that the list is a sample", out)
	}
	if strings.Contains(out, "kms key d") {
		t.Errorf("stderr %q names more than %d resources", out, maxNamedSkips)
	}
}

// The other half, as with every counter in this tool: a complete inventory
// says nothing, so the line means something when it appears.
func TestCompleteInventorySaysNothingAboutPartialCoverage(t *testing.T) {
	var buf bytes.Buffer
	reportPartialInventory(&buf, "aws", nil)
	if buf.Len() != 0 {
		t.Errorf("a complete inventory printed %q", buf.String())
	}
}

// TestGCPLocationDefaultsToEveryLocation pins the scope at the surface the
// operator actually types. The flag used to default to "global", so `qryx gcp
// --project X` inventoried one location out of dozens and reported it as the
// project's cryptography. The usage text is where this is checkable without a
// live project: `qryx gcp` with no --project fails before any client is
// built, and flag.PrintDefaults prints the default it would have used.
func TestGCPLocationDefaultsToEveryLocation(t *testing.T) {
	_, stderr := captureOutput(t, func() {
		if err := run([]string{"gcp"}); err == nil {
			t.Error("gcp without --project returned nil, want an error")
		}
	})
	if !strings.Contains(stderr, "-location") {
		t.Fatalf("usage %q does not mention -location", stderr)
	}
	if !strings.Contains(stderr, `(default "`+gcpcloud.AllLocations+`")`) {
		t.Errorf("usage %q does not default -location to every location (%q)", stderr, gcpcloud.AllLocations)
	}
	if !strings.Contains(stderr, "every location") {
		t.Errorf("usage %q does not say what the default means", stderr)
	}
}
