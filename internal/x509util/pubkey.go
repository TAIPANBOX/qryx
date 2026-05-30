// Package x509util holds certificate helpers shared by the file-based and
// network-based crypto detectors.
package x509util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// PublicKeyInfo returns a normalized algorithm name, key size in bits, and
// primitive for a certificate's public key. Unrecognized keys return ("", 0,
// PrimitiveUnknown).
func PublicKeyInfo(cert *x509.Certificate) (string, int, model.Primitive) {
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
