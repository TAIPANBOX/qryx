package sample

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
)

// uses MD5 (weak) and RSA (quantum-vulnerable)
func hashAndKey() {
	_ = md5.New()
	_, _ = rsa.GenerateKey(rand.Reader, 1024)
}
