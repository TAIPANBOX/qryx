// Package risk classifies cryptographic assets by the threat they carry.
package risk

import (
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// algoClass holds the baseline risk for a normalized algorithm name.
type algoClass struct {
	class  model.RiskClass
	sev    model.Severity
	reason string
}

// baseline maps a normalized algorithm to its risk independent of key size.
// Key-size-dependent refinements happen in Classify.
var baseline = map[string]algoClass{
	// Quantum-vulnerable asymmetric primitives (Shor's algorithm).
	"RSA":     {model.RiskQuantumVulnerable, model.SeverityHigh, "RSA is broken by a cryptographically relevant quantum computer (Shor); migrate to ML-KEM/ML-DSA"},
	"ECDSA":   {model.RiskQuantumVulnerable, model.SeverityHigh, "ECDSA is quantum-vulnerable (Shor); migrate to ML-DSA"},
	"ECDH":    {model.RiskQuantumVulnerable, model.SeverityHigh, "ECDH is quantum-vulnerable (Shor); migrate to ML-KEM"},
	"ECC":     {model.RiskQuantumVulnerable, model.SeverityHigh, "Elliptic-curve crypto is quantum-vulnerable (Shor)"},
	"DH":      {model.RiskQuantumVulnerable, model.SeverityHigh, "Diffie-Hellman is quantum-vulnerable (Shor)"},
	"DSA":     {model.RiskQuantumVulnerable, model.SeverityHigh, "DSA is quantum-vulnerable (Shor) and largely deprecated"},
	"ED25519": {model.RiskQuantumVulnerable, model.SeverityMedium, "Ed25519 is quantum-vulnerable (Shor); classically strong but plan PQC migration"},

	// Classically broken / weak primitives.
	"MD5":      {model.RiskWeak, model.SeverityHigh, "MD5 is collision-broken; do not use for security"},
	"MD4":      {model.RiskWeak, model.SeverityHigh, "MD4 is broken"},
	"SHA-1":    {model.RiskWeak, model.SeverityHigh, "SHA-1 is collision-broken; migrate to SHA-256+"},
	"DES":      {model.RiskWeak, model.SeverityHigh, "DES has a 56-bit key and is trivially brute-forced"},
	"3DES":     {model.RiskWeak, model.SeverityMedium, "3DES is deprecated (Sweet32); migrate to AES"},
	"RC4":      {model.RiskWeak, model.SeverityHigh, "RC4 is broken; remove"},
	"RC2":      {model.RiskWeak, model.SeverityHigh, "RC2 is obsolete and weak"},
	"BLOWFISH": {model.RiskWeak, model.SeverityLow, "Blowfish has a 64-bit block (Sweet32); prefer AES"},

	// Acceptable / modern.
	"AES":      {model.RiskNone, model.SeverityNone, ""},
	"CHACHA20": {model.RiskNone, model.SeverityNone, ""},
	"SHA-256":  {model.RiskNone, model.SeverityNone, ""},
	"SHA-384":  {model.RiskNone, model.SeverityNone, ""},
	"SHA-512":  {model.RiskNone, model.SeverityNone, ""},
	"SHA-224":  {model.RiskNone, model.SeverityNone, ""},
	"SHA3":     {model.RiskNone, model.SeverityNone, ""},
	"POLY1305": {model.RiskNone, model.SeverityNone, ""},
	"HMAC":     {model.RiskNone, model.SeverityNone, ""},

	// Post-quantum (NIST FIPS 203/204/205) — explicitly good.
	"ML-KEM":    {model.RiskNone, model.SeverityNone, ""},
	"ML-DSA":    {model.RiskNone, model.SeverityNone, ""},
	"SLH-DSA":   {model.RiskNone, model.SeverityNone, ""},
	"KYBER":     {model.RiskNone, model.SeverityNone, ""},
	"DILITHIUM": {model.RiskNone, model.SeverityNone, ""},
}

// NormalizeAlgorithm maps a raw algorithm string to a canonical key used by the
// risk tables. Returns "" when unrecognized.
func NormalizeAlgorithm(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "_", "-")

	switch {
	case strings.HasPrefix(s, "SHA-3"), strings.HasPrefix(s, "SHA3"):
		return "SHA3"
	case s == "SHA1" || s == "SHA-1":
		return "SHA-1"
	case s == "SHA256" || s == "SHA-256":
		return "SHA-256"
	case s == "SHA384" || s == "SHA-384":
		return "SHA-384"
	case s == "SHA512" || s == "SHA-512":
		return "SHA-512"
	case s == "SHA224" || s == "SHA-224":
		return "SHA-224"
	case s == "TRIPLEDES" || s == "DES3" || s == "DES-EDE3" || s == "3DES":
		return "3DES"
	case strings.HasPrefix(s, "ECDSA"):
		return "ECDSA"
	case strings.HasPrefix(s, "ECDH"):
		return "ECDH"
	case strings.HasPrefix(s, "ML-KEM"):
		return "ML-KEM"
	case strings.HasPrefix(s, "ML-DSA"):
		return "ML-DSA"
	}

	if _, ok := baseline[s]; ok {
		return s
	}
	return s
}
