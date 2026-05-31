package detectors

import "github.com/TAIPANBOX/qryx/internal/scan"

// Default returns the standard detector set used to scan a code tree, shared by
// `qryx scan` and container-image scanning.
func Default() []scan.Detector {
	return []scan.Detector{
		NewCertFile(),
		NewGoAST(),
		NewCryptoCall(),
		NewTLSConfig(),
		NewHardcoded(),
		NewDeps(),
		NewTerraform(),
	}
}
