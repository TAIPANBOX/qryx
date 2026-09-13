package report

import (
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// The CycloneDX 1.6 boundary.
//
// qryx's internal vocabulary is wider than CycloneDX's on purpose: "encryption"
// is what a detector can tell from an OpenSSL symbol without knowing whether
// AES was used as a block cipher or in GCM, and "library" is a thing the binary
// scanner finds (libcrypto) that the CBOM spec has no cryptographic asset type
// for. Until 2026-09-13 toComponent copied the internal strings straight into
// `cryptoProperties`, and `qryx image --format cbom` on a real image failed
// schema validation with nine errors (POL-5 of the 1.0 proving run). Every
// value written into a closed CycloneDX enum now passes through this file, and
// TestCBOMStaysInsideCycloneDX16Vocabulary walks the whole internal vocabulary
// through it against the enums copied from the schema.

// cdxPrimitive maps an internal primitive, with the algorithm name beside it,
// onto CycloneDX 1.6's `algorithmProperties.primitive` enum: drbg, mac,
// block-cipher, stream-cipher, signature, hash, pke, xof, kdf, key-agree, kem,
// ae, combiner, other, unknown. The algorithm name decides where the internal
// vocabulary is coarser than the spec's: "encryption" is a block cipher for
// AES and DES, a stream cipher for RC4, public-key encryption for RSA, and
// "other" for a symbol like EVP_CIPHER that names the API rather than a
// cipher; "key-exchange" is key agreement for ECDH and DH and a KEM for
// ML-KEM; a "hash" named HMAC is a MAC.
func cdxPrimitive(algorithm string, p model.Primitive) string {
	name := strings.ToUpper(strings.TrimSpace(algorithm))
	base := name
	if i := strings.IndexAny(name, "-_ "); i > 0 && !strings.HasPrefix(name, "3DES") && !strings.HasPrefix(name, "ML-") && !strings.HasPrefix(name, "SHA-") && !strings.HasPrefix(name, "SM") {
		base = name[:i]
	}
	switch p {
	case model.PrimitiveSignature:
		return "signature"
	case model.PrimitiveHash:
		if base == "HMAC" || base == "CMAC" || base == "GMAC" || base == "POLY1305" {
			return "mac"
		}
		return "hash"
	case model.PrimitiveKeyExch:
		if strings.HasPrefix(name, "ML-KEM") || strings.HasPrefix(name, "KYBER") || strings.HasPrefix(name, "HQC") || strings.HasPrefix(name, "BIKE") {
			return "kem"
		}
		return "key-agree"
	case model.PrimitiveEncryption:
		switch {
		case strings.Contains(name, "GCM") || strings.Contains(name, "CCM") || strings.Contains(name, "POLY1305") || strings.Contains(name, "OCB") || strings.Contains(name, "SIV"):
			return "ae"
		}
		switch base {
		case "AES", "DES", "3DES", "TDES", "TRIPLE", "BLOWFISH", "CAMELLIA", "CAST5", "CAST", "IDEA", "RC2", "RC5", "RC6", "SEED", "ARIA", "SM4", "TWOFISH", "SERPENT", "SKIPJACK":
			return "block-cipher"
		case "RC4", "CHACHA20", "CHACHA", "SALSA20", "XSALSA20":
			return "stream-cipher"
		case "RSA", "ELGAMAL", "ECIES", "SM2", "PAILLIER":
			return "pke"
		}
		return "other"
	case model.PrimitiveTLS:
		// A protocol has no algorithm primitive; a caller that reaches here with
		// an algorithm-typed asset gets the nearest honest word.
		return "other"
	case model.PrimitiveUnknown, "":
		return "unknown"
	}
	return "other"
}

// cdxProtocolType maps a protocol asset's name onto `protocolProperties.type`:
// tls, ssh, ipsec, ike, sstp, wpa, other, unknown.
func cdxProtocolType(algorithm string) string {
	name := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(name, "TLS") || strings.Contains(name, "SSL") || strings.Contains(name, "HTTPS"):
		return "tls"
	case strings.Contains(name, "SSH"):
		return "ssh"
	case strings.Contains(name, "IPSEC"):
		return "ipsec"
	case strings.Contains(name, "IKE"):
		return "ike"
	case strings.Contains(name, "WPA"):
		return "wpa"
	}
	return "other"
}

// cdxKeyMaterialType maps a key asset onto `relatedCryptoMaterialProperties.type`.
// qryx knows a key was found and, sometimes, that it was private; it does not
// know a public key from a secret key, so the wide word is the honest one.
func cdxKeyMaterialType(algorithm string) string {
	name := strings.ToLower(algorithm)
	switch {
	case strings.Contains(name, "private"):
		return "private-key"
	case strings.Contains(name, "public"):
		return "public-key"
	}
	return "key"
}
