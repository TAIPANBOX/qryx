package sample

import (
	"crypto/md5" // #nosec G501 -- detector fixture: weak algorithm this scanner must detect, not used for security
	"crypto/rand"
	"crypto/rsa"
)

// uses MD5 (weak) and RSA-1024 (weak: below the 2048-bit minimum)
func hashAndKey() {
	_ = md5.New()                             // #nosec G401 -- detector fixture: weak algorithm this scanner must detect, not used for security
	_, _ = rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- detector fixture: sub-floor RSA key size this scanner must detect, not used for security
}
