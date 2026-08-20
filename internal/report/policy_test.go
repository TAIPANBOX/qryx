package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/policy"
)

// Violations and firstLocation had never been run. This is the text a person
// reads to decide whether a policy passed, and it is the last thing between a
// failing scan and somebody believing it passed.
//
// The word PASS is the whole risk. Everything else here is formatting, and a
// misaligned column is visible the moment anybody looks. A report that says
// PASS over a list of violations is not visible at all: it is the answer the
// reader was hoping for.

func TestNoViolationsSaysPassAndNamesThePolicy(t *testing.T) {
	var buf bytes.Buffer
	Violations(&buf, "pq-readiness", nil)
	out := buf.String()

	if !strings.Contains(out, "PASS") {
		t.Fatalf("an empty violation list did not say PASS:\n%s", out)
	}
	if strings.Contains(out, "FAIL") {
		t.Fatalf("an empty violation list said FAIL:\n%s", out)
	}
	if !strings.Contains(out, "pq-readiness") {
		t.Fatalf("the policy is not named, so a report over several policies "+
			"cannot be attributed:\n%s", out)
	}
}

func TestViolationsSayFailAndAreAllPrinted(t *testing.T) {
	vs := []policy.Violation{
		{
			Rule: "no-rsa-under-3072", Asset: "RSA-2048",
			Severity: model.SeverityHigh, Message: "key too short",
			Locations: []string{"internal/tls/server.go:41"},
		},
		{
			Rule: "no-static-keys", Asset: "Ed25519",
			Severity: model.SeverityCritical, Message: "private key in source",
			Locations: []string{"cmd/agent/main.go:12", "cmd/agent/boot.go:8", "pkg/x/y.go:3"},
		},
	}
	var buf bytes.Buffer
	Violations(&buf, "pq-readiness", vs)
	out := buf.String()

	if strings.Contains(out, "PASS") {
		t.Fatalf("two violations were reported as PASS:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Fatalf("violations were not reported as FAIL:\n%s", out)
	}
	if !strings.Contains(out, "2 violation") {
		t.Fatalf("the count is missing or wrong, and a reader who trusts the "+
			"header will stop reading before the list:\n%s", out)
	}
	for _, want := range []string{
		"no-rsa-under-3072", "RSA-2048", "key too short",
		"no-static-keys", "Ed25519", "private key in source",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q is missing from the report:\n%s", want, out)
		}
	}
}

// firstLocation prints one place and says how many more there are. Dropping
// the "+N" would make a violation in twelve files look like a violation in
// one, which is the difference between a fix and a sweep.
func TestFirstLocationSaysHowManyItIsNotShowing(t *testing.T) {
	cases := []struct {
		name string
		locs []string
		want string
	}{
		{"nothing to point at", nil, ""},
		{"an empty list is not a location", []string{}, ""},
		{"one place is printed alone", []string{"a.go:1"}, "a.go:1"},
		{"two places count the one not shown", []string{"a.go:1", "b.go:2"}, "a.go:1 (+1)"},
		{"twelve places count the eleven not shown", []string{
			"a.go:1", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
		}, "a.go:1 (+11)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := firstLocation(policy.Violation{Locations: c.locs})
			if got != c.want {
				t.Fatalf("firstLocation(%v) = %q, want %q: a violation in "+
					"several files must not read as a violation in one",
					c.locs, got, c.want)
			}
		})
	}
}
