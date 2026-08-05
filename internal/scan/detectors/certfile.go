package detectors

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
	"github.com/TAIPANBOX/qryx/internal/x509util"
)

// CertFile parses PEM certificates and reports the signature algorithm, public
// key, and expiry. This is the highest-signal Phase 0 detector: real assets,
// no guessing.
type CertFile struct {
	// unparsed counts files holding at least one CERTIFICATE block x509
	// rejected. Counted per file, not per block, so it can be added to the
	// walker's other per-file counts.
	unparsed int
}

func NewCertFile() *CertFile { return &CertFile{} }

func (c *CertFile) Name() string { return "certfile" }

// Unparsed implements scan.UnparsedReporter.
func (c *CertFile) Unparsed() int { return c.unparsed }

func (c *CertFile) Wants(path string) bool {
	switch filepath.Ext(path) {
	case ".pem", ".crt", ".cer":
		return true
	}
	return false
}

func (c *CertFile) Detect(f scan.File) []model.Finding {
	var out []model.Finding
	rejected := false
	rest := f.Content
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// A certificate qryx could not parse is not a certificate with
			// nothing wrong in it; the walker reports the difference.
			rejected = true
			continue
		}
		out = append(out, c.findingsForCert(f.Path, cert)...)
	}
	if rejected {
		c.unparsed++
	}
	return out
}

func (c *CertFile) findingsForCert(path string, cert *x509.Certificate) []model.Finding {
	var out []model.Finding

	algo, size, prim := x509util.PublicKeyInfo(cert)
	if algo != "" {
		out = append(out, model.Finding{
			Asset: model.Asset{
				Type:      model.TypeCertificate,
				Algorithm: algo,
				KeySize:   size,
				Primitive: prim,
			},
			Location: model.Location{File: path},
			Evidence: fmt.Sprintf("certificate subject %q, %s key", cert.Subject.CommonName, algo),
			Source:   c.Name(),
		})
	}

	// Expiry is a context risk, asserted directly.
	if now := time.Now(); cert.NotAfter.Before(now) {
		out = append(out, model.Finding{
			Asset: model.Asset{
				Type:      model.TypeCertificate,
				Algorithm: algo,
				KeySize:   size,
				Primitive: prim,
			},
			Location: model.Location{File: path},
			Evidence: fmt.Sprintf("certificate %q expired %s", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02")),
			Source:   c.Name(),
			Risk: model.Risk{
				Class:    model.RiskExpired,
				Severity: model.SeverityHigh,
				Reason:   "certificate is past its NotAfter date",
			},
		})
	}

	return out
}
