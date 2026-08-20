package main

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/policy"
)

// Two helpers on the CLI's own path. Small, and each decides something a
// reader of a report depends on.

func TestEverySeverityAnOperatorCanTypeIsUnderstood(t *testing.T) {
	t.Parallel()

	// This parses --min-severity. An unrecognised value must be REFUSED, not
	// quietly resolved to something: a typo silently becoming "low" means a
	// scan an operator believes is filtered to critical findings reports
	// everything, and a typo becoming "critical" means it reports almost
	// nothing while they believe they asked for everything.
	for in, want := range map[string]model.Severity{
		"low":      model.SeverityLow,
		"medium":   model.SeverityMedium,
		"high":     model.SeverityHigh,
		"critical": model.SeverityCritical,
	} {
		got, ok := parseSeverity(in)
		if !ok {
			t.Errorf("%q must be understood", in)
			continue
		}
		if got != want {
			t.Errorf("%q parsed to %v, want %v", in, got, want)
		}
	}

	for _, bad := range []string{"", "LOW", "Critical", "sev1", "none", "urgent", " high"} {
		if _, ok := parseSeverity(bad); ok {
			t.Errorf("%q was accepted; an unrecognised severity must be refused so the "+
				"operator is told rather than given a filter they did not ask for", bad)
		}
	}
}

func TestAPolicyWithoutANameIsLabelledByWhatTheOperatorTyped(t *testing.T) {
	t.Parallel()

	// The name reaches the report. A policy loaded from a file with no `name:`
	// would otherwise appear as an empty string, and a finding attributed to
	// nothing cannot be traced back to the rule that raised it.
	if got := policyName("./policies/prod.yaml", policy.Policy{}); got != "./policies/prod.yaml" {
		t.Errorf("got %q, want the argument the operator typed", got)
	}
	if got := policyName("./policies/prod.yaml", policy.Policy{Name: "prod-baseline"}); got != "prod-baseline" {
		t.Errorf("got %q, want the policy's own name", got)
	}
}
