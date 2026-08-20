package risk

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// Apply had never been run by any test. It is four lines and it decides
// something that cannot be seen once it is wrong: whether a finding keeps the
// risk its detector asserted, or gets the generic classifier's answer instead.
//
// The two kinds of detector are not interchangeable. An algorithm detector
// sees "RSA-2048" and nothing else, so the classifier is the only thing that
// can rate it. A context detector saw the reason: a certificate that has
// already expired, a key hardcoded in a source file, a TLS config that
// negotiates down. Reclassifying those by algorithm alone throws the reason
// away and keeps the shape, which is why nothing downstream would notice.

func TestApplyRatesOnlyWhatNothingHasRatedYet(t *testing.T) {
	// A context detector's verdict: the algorithm here is fine, and the
	// finding is critical for a reason the algorithm cannot carry.
	asserted := model.Risk{
		Class:    model.RiskNone,
		Severity: model.SeverityCritical,
		Reason:   "private key hardcoded in source",
	}
	findings := []model.Finding{
		{Source: "hardcoded", Asset: model.Asset{Algorithm: "Ed25519"}, Risk: asserted},
		{Source: "goast", Asset: model.Asset{Algorithm: "RSA-2048"}},
	}

	got := Apply(findings)

	if got[0].Risk != asserted {
		t.Fatalf("Apply overwrote a detector's own verdict.\n got: %+v\nwant: %+v\n"+
			"The detector saw why this was critical. The classifier sees only "+
			"Ed25519, which is not what the finding was about.", got[0].Risk, asserted)
	}
	if got[1].Risk.Class == "" {
		t.Fatal("an unrated finding stayed unrated: an algorithm detector leaves " +
			"Risk empty precisely so this classifies it")
	}
	if want := Classify(findings[1].Asset); got[1].Risk != want {
		t.Fatalf("unrated finding classified as %+v, want %+v", got[1].Risk, want)
	}
}

// In place, and returning the same slice. A caller that ignores the return
// value must still see the classification, and a caller that uses it must not
// get a copy that diverges from the original.
func TestApplyClassifiesInPlaceAndHandsBackTheSameSlice(t *testing.T) {
	findings := []model.Finding{{Asset: model.Asset{Algorithm: "RSA-2048"}}}
	got := Apply(findings)

	if findings[0].Risk.Class == "" {
		t.Fatal("the caller's own slice was not classified: Apply documents " +
			"itself as in place, and a caller that ignores the return value " +
			"would silently report every finding as unrated")
	}
	if len(got) != len(findings) || &got[0] != &findings[0] {
		t.Fatal("Apply returned a different slice than it was given")
	}
}

// Nothing to do is not a crash. Both shapes reach this: a scan that found
// nothing, and a caller that has not read anything yet.
func TestApplyOnNothing(t *testing.T) {
	if got := Apply(nil); got != nil {
		t.Fatalf("Apply(nil) = %v, want nil", got)
	}
	if got := Apply([]model.Finding{}); len(got) != 0 {
		t.Fatalf("Apply(empty) returned %d findings", len(got))
	}
}
