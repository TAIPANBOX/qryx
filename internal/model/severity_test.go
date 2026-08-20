package model

import "testing"

// Severity.String had never been run. It is the word that appears in every
// human report and in the exit-code decision, and it is an int underneath, so
// nothing about a wrong one looks wrong.
//
// The ordering matters as much as the words. Severity is an iota, and a
// constant inserted in the middle renumbers everything after it: a report
// would go on rendering perfectly formatted rows in which "critical" now means
// what "high" used to.
func TestEverySeverityHasItsOwnWord(t *testing.T) {
	cases := []struct {
		s    Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
		{SeverityNone, "none"},
	}
	seen := map[string]Severity{}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(c.s), got, c.want)
		}
		if prev, dup := seen[c.want]; dup {
			t.Errorf("%q is the word for both Severity(%d) and Severity(%d): "+
				"two levels reading as one is invisible in every report",
				c.want, int(prev), int(c.s))
		}
		seen[c.want] = c.s
	}
}

// The order is the claim. A report sorted by severity, and any threshold that
// decides an exit code, both depend on critical outranking high and on none
// being the bottom.
func TestSeveritiesRankInTheOrderReportsRelyOn(t *testing.T) {
	ordered := []Severity{
		SeverityNone, SeverityInfo, SeverityLow,
		SeverityMedium, SeverityHigh, SeverityCritical,
	}
	for i := 1; i < len(ordered); i++ {
		if !(ordered[i-1] < ordered[i]) {
			t.Fatalf("%s is not below %s. A threshold that fails a build above "+
				"'high' would be letting criticals through, and the report "+
				"would look entirely normal",
				ordered[i-1], ordered[i])
		}
	}
}

// A value from outside the enum reads as none rather than as an empty string.
// An empty severity column is a row a reader skips.
func TestAnUnknownSeverityIsNoneAndNotBlank(t *testing.T) {
	for _, s := range []Severity{Severity(-1), Severity(99)} {
		if got := s.String(); got != "none" {
			t.Fatalf("Severity(%d).String() = %q, want \"none\"", int(s), got)
		}
	}
}
