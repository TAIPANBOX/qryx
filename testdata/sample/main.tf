resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 1024 # weak: below the 2048-bit minimum
}

resource "aws_kms_key" "signing" {
  description              = "ecc signing key"
  customer_master_key_spec = "ECC_NIST_P256"
}
