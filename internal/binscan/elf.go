// Package binscan discovers cryptography in compiled binaries. This increment
// handles ELF (Linux); it is a connector like internal/probe, not a file
// detector — binaries are identified by magic bytes, read from disk, and parsed
// structurally rather than scanned as text.
package binscan

import (
	"debug/elf"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
)

// elfMagic is the leading byte sequence of every ELF file.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// cryptoLibs maps a needed-library name substring to the algorithm family it
// implies, recorded as inventory.
var cryptoLibs = []struct{ needle, algo string }{
	{"libcrypto", "RSA"},
	{"libssl", "TLS"},
	{"libgnutls", "TLS"},
	{"libmbedtls", "TLS"},
	{"libsodium", "Ed25519"},
}

// symRule maps a dynamic-symbol prefix to an algorithm and primitive.
type symRule struct {
	prefix string
	algo   string
	prim   model.Primitive
}

// symRules are checked in order; the first matching prefix wins. Ordered so more
// specific prefixes precede broader ones (SHA1 before SHA, EC before ED).
var symRules = []symRule{
	{"MD5", "MD5", model.PrimitiveHash},
	{"SHA1", "SHA-1", model.PrimitiveHash},
	{"SHA256", "SHA-256", model.PrimitiveHash},
	{"SHA512", "SHA-512", model.PrimitiveHash},
	{"RSA", "RSA", model.PrimitiveSignature},
	{"ECDSA", "ECDSA", model.PrimitiveSignature},
	{"EC_", "ECDSA", model.PrimitiveSignature},
	{"ED25519", "Ed25519", model.PrimitiveSignature},
	{"DSA", "DSA", model.PrimitiveSignature},
	{"DH_", "DH", model.PrimitiveKeyExch},
	{"DES", "DES", model.PrimitiveEncryption},
	{"RC4", "RC4", model.PrimitiveEncryption},
}

// Scan walks each path (file or directory) and returns crypto findings from
// every ELF binary it contains. Non-ELF files are skipped silently.
func Scan(paths []string) ([]model.Finding, error) {
	var out []model.Finding
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || !d.Type().IsRegular() {
					return nil
				}
				out = append(out, scanFile(path)...)
				return nil
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		out = append(out, scanFile(p)...)
	}
	return out, nil
}

// scanFile parses one file if it is an ELF binary, returning its findings.
func scanFile(path string) []model.Finding {
	if !isELF(path) {
		return nil
	}
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []model.Finding
	libs, _ := f.ImportedLibraries()
	out = append(out, librariesToFindings(path, libs)...)

	syms, _ := f.ImportedSymbols()
	names := make([]string, len(syms))
	for i, s := range syms {
		names[i] = s.Name
	}
	out = append(out, cryptoFromSymbols(path, names)...)
	return out
}

// isELF reports whether the file begins with the ELF magic.
func isELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := f.Read(hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == string(elfMagic)
}

func librariesToFindings(path string, libs []string) []model.Finding {
	var out []model.Finding
	for _, lib := range libs {
		for _, cl := range cryptoLibs {
			if strings.Contains(lib, cl.needle) {
				out = append(out, model.Finding{
					Asset:    model.Asset{Type: model.TypeLibrary, Algorithm: cl.algo, Primitive: model.PrimitiveUnknown},
					Location: model.Location{File: path},
					Evidence: "links " + lib,
					Source:   "elf",
				})
				break
			}
		}
	}
	return out
}

// cryptoFromSymbols maps imported dynamic symbols to algorithm findings,
// emitting at most one finding per algorithm to avoid per-symbol noise.
func cryptoFromSymbols(path string, symbols []string) []model.Finding {
	seen := map[string]bool{}
	var out []model.Finding
	for _, name := range symbols {
		for _, r := range symRules {
			if strings.HasPrefix(name, r.prefix) {
				if !seen[r.algo] {
					seen[r.algo] = true
					out = append(out, model.Finding{
						Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: r.algo, Primitive: r.prim},
						Location: model.Location{File: path},
						Evidence: "imports " + name,
						Source:   "elf",
					})
				}
				break
			}
		}
	}
	return out
}
