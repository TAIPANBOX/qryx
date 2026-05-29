package detectors

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"time"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// CertFile parses PEM certificates and reports the signature algorithm, public
// key, and expiry. This is the highest-signal Phase 0 detector: real assets,
// no guessing.
type CertFile struct{}

func NewCertFile() *CertFile { return &CertFile{} }

func (c *CertFile) Name() string { return "certfile" }

func (c *CertFile) Wants(path string) bool {
	switch filepath.Ext(path) {
	case ".pem", ".crt", ".cer":
		return true
	}
	return false
}

func (c *CertFile) Detect(f scan.File) []model.Finding {
	var out []model.Finding
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
			continue
		}
		out = append(out, c.findingsForCert(f.Path, cert)...)
	}
	return out
}

func (c *CertFile) findingsForCert(path string, cert *x509.Certificate) []model.Finding {
	var out []model.Finding

	algo, size, prim := publicKeyInfo(cert)
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

// publicKeyInfo returns a normalized algorithm name, key size in bits, and
// primitive for a certificate's public key.
func publicKeyInfo(cert *x509.Certificate) (string, int, model.Primitive) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen(), model.PrimitiveSignature
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize, model.PrimitiveSignature
	case ed25519.PublicKey:
		return "Ed25519", 256, model.PrimitiveSignature
	default:
		return "", 0, model.PrimitiveUnknown
	}
}
