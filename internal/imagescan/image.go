// Package imagescan scans a local container image tarball (the output of
// `docker save` or an OCI image layout) for cryptography. An image is just
// layered filesystems: this package extracts the layers to a temp directory and
// runs the existing code and binary scanners over them — no new detection
// logic, images are simply another source.
package imagescan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/binscan"
	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
	"github.com/TAIPANBOX/qryx/internal/scan/detectors"
)

const (
	maxFileBytes  = 32 << 20 // per-file extraction cap
	maxTotalBytes = 2 << 30  // per-image extraction cap (tar-bomb defense)
	ustarOffset   = 257      // offset of the "ustar" magic in a tar header
)

// Scan extracts each image tarball and returns the crypto findings discovered
// in its layers. A tar that cannot be opened is reported to stderr and skipped.
func Scan(tars []string) ([]model.Finding, error) {
	var out []model.Finding
	for _, t := range tars {
		findings, err := scanImage(t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "qryx: %s: %v\n", t, err)
			continue
		}
		out = append(out, findings...)
	}
	return out, nil
}

func scanImage(imageTar string) ([]model.Finding, error) {
	root, err := os.MkdirTemp("", "qryx-image-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)

	if err := extractImage(imageTar, root); err != nil {
		return nil, err
	}

	codeRes, err := scan.New(detectors.Default()...).Scan(root)
	if err != nil {
		return nil, err
	}
	findings := codeRes.Findings

	binFindings, err := binscan.Scan([]string{root})
	if err != nil {
		return nil, err
	}
	findings = append(findings, binFindings...)

	// Rewrite temp paths to image-relative locations.
	for i := range findings {
		rel, err := filepath.Rel(root, findings[i].Location.File)
		if err != nil {
			rel = findings[i].Location.File
		}
		findings[i].Location.File = imageTar + "::" + rel
	}
	return findings, nil
}

// extractImage walks the outer tar and extracts every layer (an entry that is
// itself a tar or gzip) into root, overlaying later layers onto earlier ones.
func extractImage(imageTar, root string) error {
	f, err := os.Open(imageTar)
	if err != nil {
		return err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Buffer the entry (bounded) to sniff whether it is a layer tar.
		buf, err := readCapped(tr, maxFileBytes)
		if err != nil {
			return err
		}
		layer, err := asTarReader(buf)
		if err != nil || layer == nil {
			continue // not a layer (manifest.json, config, etc.)
		}
		if err := extractLayer(layer, root, &total); err != nil {
			return err
		}
	}
	return nil
}

// asTarReader returns a tar.Reader if data is a (possibly gzipped) tar archive,
// or nil if it is not.
func asTarReader(data []byte) (*tar.Reader, error) {
	r := io.Reader(bytes.NewReader(data))
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		// Peek the decompressed head for the ustar magic.
		head, _ := readCapped(gz, ustarOffset+8)
		if !hasUstarMagic(head) {
			return nil, nil
		}
		gz2, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return tar.NewReader(gz2), nil
	}
	if !hasUstarMagic(data) {
		return nil, nil
	}
	return tar.NewReader(bytes.NewReader(data)), nil
}

func hasUstarMagic(b []byte) bool {
	return len(b) >= ustarOffset+5 && string(b[ustarOffset:ustarOffset+5]) == "ustar"
}

// extractLayer writes the regular files of one layer tar into root, with
// path-traversal and size guards.
func extractLayer(tr *tar.Reader, root string, total *int64) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Only regular files; never create or follow links/devices.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if strings.HasPrefix(filepath.Base(hdr.Name), ".wh.") {
			continue // OCI whiteout marker
		}
		dest, ok := safeJoin(root, hdr.Name)
		if !ok {
			continue // path escapes root — drop it
		}
		if *total+hdr.Size > maxTotalBytes {
			return fmt.Errorf("image exceeds %d-byte extraction limit", int64(maxTotalBytes))
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		n, err := writeCapped(dest, tr, maxFileBytes)
		if err != nil {
			return err
		}
		*total += n
	}
}

// safeJoin joins name onto root, returning ok=false if the result would escape
// root (absolute path or .. traversal).
func safeJoin(root, name string) (string, bool) {
	clean := filepath.Clean("/" + name) // anchor to make ".." harmless
	dest := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return dest, true
}

// readCapped reads up to max bytes from r.
func readCapped(r io.Reader, max int) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, int64(max)))
}

// writeCapped writes up to max bytes from r into path, returning bytes written.
func writeCapped(path string, r io.Reader, max int) (int64, error) {
	out, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, io.LimitReader(r, int64(max)))
}
