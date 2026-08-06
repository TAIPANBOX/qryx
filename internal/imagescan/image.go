// Package imagescan scans a local container image tarball (the output of
// `docker save` or an OCI image layout) for cryptography. An image is just
// layered filesystems: this package extracts the layers to a temp directory and
// runs the existing code and binary scanners over them: no new detection
// logic, images are simply another source.
package imagescan

import (
	"archive/tar"
	"bufio"
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
	maxTotalBytes = 2 << 30 // per-image extraction cap (tar-bomb defense)
	ustarOffset   = 257     // offset of the "ustar" magic in a tar header
	sniffBytes    = 4096    // read-ahead used to recognize a layer, must exceed ustarOffset+5
)

// maxFileBytes caps a single file extracted out of a layer. A var rather than a
// const so a test can drive a realistic image shape (a layer larger than the
// cap) with a few kilobytes instead of writing 32 MiB of zeroes on every CI
// run. Nothing outside this package changes it.
var maxFileBytes int64 = 32 << 20

// extractStats records what extraction could not do, so an image that was only
// partly examined is never presented as one with nothing in it.
type extractStats struct {
	written  int64 // bytes written, the tar-bomb budget
	oversize int   // files skipped for exceeding maxFileBytes
}

// Scan extracts each image tarball and returns the crypto findings discovered
// in its layers.
//
// An image that cannot be extracted is an error, not a skip. Until 2026-08-05
// it was reported on stderr and dropped, so the command printed zero findings
// on stdout and exited 0: the same output as an image with no cryptography in
// it. That is not an edge case. The outer tar entry was buffered whole and
// capped at maxFileBytes, and every layer of a Debian- or Ubuntu-based image is
// larger than 32 MiB, so the buffer was truncated, tar.Next reported
// io.ErrUnexpectedEOF, and the operator was told the image was clean.
func Scan(tars []string) ([]model.Finding, error) {
	var out []model.Finding
	for _, t := range tars {
		findings, st, err := scanImage(t)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t, err)
		}
		if st.oversize > 0 {
			fmt.Fprintf(os.Stderr, "qryx: %s: %d file(s) larger than the %d-byte per-file cap were not extracted. This scan says nothing about them.\n",
				t, st.oversize, maxFileBytes)
		}
		out = append(out, findings...)
	}
	return out, nil
}

func scanImage(imageTar string) ([]model.Finding, extractStats, error) {
	var st extractStats
	root, err := os.MkdirTemp("", "qryx-image-*")
	if err != nil {
		return nil, st, err
	}
	defer os.RemoveAll(root)

	if err := extractImage(imageTar, root, &st); err != nil {
		return nil, st, err
	}

	codeRes, err := scan.New(detectors.Default()...).Scan(root)
	if err != nil {
		return nil, st, err
	}
	findings := codeRes.Findings

	binFindings, err := binscan.Scan([]string{root})
	if err != nil {
		return nil, st, err
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
	return findings, st, nil
}

// extractImage walks the outer tar and extracts every layer (an entry that is
// itself a tar or gzip) into root, overlaying later layers onto earlier ones.
func extractImage(imageTar, root string, st *extractStats) error {
	f, err := os.Open(imageTar) // #nosec G304 -- imageTar is the operator's own CLI argument (qryx image scan <tar>), same trust model as any local file the invoking user names
	if err != nil {
		return err
	}
	defer f.Close()

	tr := tar.NewReader(f)
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
		// Recognize the layer without buffering it: it is read straight through
		// the outer tar reader as it is extracted. Buffering the whole entry
		// first is what made a 32 MiB cap decide whether a real image could be
		// scanned at all, and it also held a layer in memory for no reason.
		layer, err := asTarReader(tr)
		if err != nil || layer == nil {
			continue // not a layer (manifest.json, config, etc.)
		}
		if err := extractLayer(layer, root, st); err != nil {
			return err
		}
	}
	return nil
}

// asTarReader returns a tar.Reader over r when r carries a (possibly gzipped)
// tar archive, or nil when it does not. It reads only far enough to recognize
// one, sniffBytes at most; everything after that is consumed by the returned
// reader as the layer is extracted, so the layer is never held whole and its
// size is not bounded by any cap here.
func asTarReader(r io.Reader) (*tar.Reader, error) {
	buffered := bufio.NewReaderSize(r, sniffBytes)
	var body io.Reader = buffered
	if magic, _ := buffered.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, err
		}
		body = gz
	}
	// Peek the (decompressed) head for the ustar magic. A short read is not an
	// error here: it only means this entry is too small to be a layer.
	head := bufio.NewReaderSize(body, sniffBytes)
	magic, _ := head.Peek(ustarOffset + 5)
	if !hasUstarMagic(magic) {
		return nil, nil
	}
	return tar.NewReader(head), nil
}

func hasUstarMagic(b []byte) bool {
	return len(b) >= ustarOffset+5 && string(b[ustarOffset:ustarOffset+5]) == "ustar"
}

// extractLayer writes the regular files of one layer tar into root, with
// path-traversal and size guards.
func extractLayer(tr *tar.Reader, root string, st *extractStats) error {
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
			continue // path escapes root, drop it
		}
		if hdr.Size > maxFileBytes {
			// Skipped and counted, not truncated: half a binary parses as a
			// binary with no crypto in it, which is the exact failure this file
			// is being fixed for.
			st.oversize++
			continue
		}
		if st.written+hdr.Size > maxTotalBytes {
			return fmt.Errorf("image exceeds %d-byte extraction limit", int64(maxTotalBytes))
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return err
		}
		n, err := writeCapped(dest, tr, maxFileBytes)
		if err != nil {
			return err
		}
		st.written += n
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

// writeCapped writes up to max bytes from r into path, returning bytes written.
// The cap is a backstop against a header that understates its own entry:
// extractLayer skips anything declaring more than max, so a file that reaches
// here is expected to fit.
func writeCapped(path string, r io.Reader, max int64) (int64, error) {
	out, err := os.Create(path) // #nosec G304 -- path is always the output of safeJoin, which rejects any name that would escape root (path-traversal guard); do not remove
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, io.LimitReader(r, max))
}
