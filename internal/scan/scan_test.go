package scan_test

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
	"github.com/TAIPANBOX/qryx/internal/scan/detectors"
)

func TestScanSample(t *testing.T) {
	s := scan.New(
		detectors.NewCertFile(),
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
		"MD5":         model.RiskWeak,
		"RSA":         model.RiskQuantumVulnerable,
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
