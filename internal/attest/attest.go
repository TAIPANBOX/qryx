// Package attest signs and verifies compliance-evidence digests. It is
// stdlib-only (ed25519, ECDSA P-256, or ML-DSA (FIPS 204), PKCS#8 keys),
// adding authenticity on top of the integrity digest the evidence document
// already carries.
package attest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

const (
	algEd25519 = "ed25519"
	algECDSA   = "ecdsa-p256"
	// mldsaAlgPrefix labels an ML-DSA signature by its FIPS 204 security
	// level (e.g. "ml-dsa-44"/"ml-dsa-65"/"ml-dsa-87"); see mldsaAlg. All
	// three levels are accepted -- unlike the single ECDSA curve enforced
	// below, they are equally standardized, safe choices trading off
	// signature size against security margin, not a case of picking one
	// recommended option among weaker alternatives.
	mldsaAlgPrefix = "ml-dsa-"
)

// mldsaAlg is params' Signature.Alg label, e.g. "ml-dsa-44" for
// mldsa.MLDSA44 -- lowercased from Parameters.String() ("ML-DSA-44") so it
// always matches whichever of the three FIPS 204 levels a key was generated
// for, with no separate mapping table to fall out of sync.
func mldsaAlg(params mldsa.Parameters) string {
	return strings.ToLower(params.String())
}

// Signature is a detached signature over an evidence digest, carrying the
// public key (SPKI DER) so it is self-verifying against a trusted fingerprint.
type Signature struct {
	Alg       string `json:"alg"`
	Value     string `json:"value"`
	PublicKey string `json:"publicKey"`
}

// Signer holds a parsed private key and its algorithm.
type Signer struct {
	alg   string
	ed    ed25519.PrivateKey
	ec    *ecdsa.PrivateKey
	mldsa *mldsa.PrivateKey
	spki  []byte
}

// LoadSigner reads a PKCS#8 PEM private key (ed25519, ECDSA P-256, or
// ML-DSA).
func LoadSigner(pemPath string) (*Signer, error) {
	raw, err := os.ReadFile(pemPath) // #nosec G304 -- pemPath is the operator's own --sign-key/--verify CLI argument, same trust model as any local key file the invoking user names
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", pemPath)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 key: %w", err)
	}

	s := &Signer{}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		s.alg, s.ed = algEd25519, k
		s.spki, err = x509.MarshalPKIXPublicKey(k.Public())
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("unsupported ECDSA curve %s; use P-256", k.Curve.Params().Name)
		}
		s.alg, s.ec = algECDSA, k
		s.spki, err = x509.MarshalPKIXPublicKey(k.Public())
	case *mldsa.PrivateKey:
		s.alg, s.mldsa = mldsaAlg(k.PublicKey().Parameters()), k
		s.spki, err = x509.MarshalPKIXPublicKey(k.Public())
	default:
		return nil, fmt.Errorf("unsupported key type %T; use ed25519, ECDSA P-256, or ML-DSA", key)
	}
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return s, nil
}

// Sign returns a detached signature over payload.
func (s *Signer) Sign(payload []byte) (Signature, error) {
	var sigBytes []byte
	switch {
	case s.alg == algEd25519:
		sigBytes = ed25519.Sign(s.ed, payload)
	case s.alg == algECDSA:
		h := sha256.Sum256(payload)
		b, err := ecdsa.SignASN1(rand.Reader, s.ec, h[:])
		if err != nil {
			return Signature{}, err
		}
		sigBytes = b
	case strings.HasPrefix(s.alg, mldsaAlgPrefix):
		// rand.Reader, not SignDeterministic: matches the hedged (default)
		// signing mode FIPS 204 recommends, the same "let randomized
		// signing apply where the algorithm supports it" choice ECDSA
		// above already makes.
		b, err := s.mldsa.Sign(rand.Reader, payload, nil)
		if err != nil {
			return Signature{}, err
		}
		sigBytes = b
	default:
		return Signature{}, fmt.Errorf("unsupported signer algorithm %q", s.alg)
	}
	return Signature{
		Alg:       s.alg,
		Value:     base64.StdEncoding.EncodeToString(sigBytes),
		PublicKey: base64.StdEncoding.EncodeToString(s.spki),
	}, nil
}

// Verify checks sig over payload using the public key embedded in sig.
func Verify(payload []byte, sig Signature) error {
	spki, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	value, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	switch {
	case sig.Alg == algEd25519:
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not ed25519")
		}
		if !ed25519.Verify(k, payload, value) {
			return fmt.Errorf("signature verification failed")
		}
	case sig.Alg == algECDSA:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not ECDSA")
		}
		h := sha256.Sum256(payload)
		if !ecdsa.VerifyASN1(k, h[:], value) {
			return fmt.Errorf("signature verification failed")
		}
	case strings.HasPrefix(sig.Alg, mldsaAlgPrefix):
		k, ok := pub.(*mldsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not ML-DSA")
		}
		if err := mldsa.Verify(k, payload, value, nil); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	default:
		return fmt.Errorf("unsupported signature algorithm %q", sig.Alg)
	}
	return nil
}

// Fingerprint is a short sha256 of the signing public key, for trust display.
func Fingerprint(sig Signature) string {
	spki, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil {
		return "sha256:invalid"
	}
	sum := sha256.Sum256(spki)
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}
