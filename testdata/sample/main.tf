resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 1024 # weak: below the 2048-bit minimum
}

resource "aws_kms_key" "signing" {
  description              = "ecc signing key"
  customer_master_key_spec = "ECC_NIST_P256"
}

resource "google_kms_crypto_key" "rsa" {
  name     = "rsa-key"
  key_ring = "projects/p/locations/global/keyRings/r"

  version_template {
    algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
  }
}
