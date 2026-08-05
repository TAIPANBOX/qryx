package imagescan

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTar writes the given files as a tar archive to w.
func writeTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// dockerSaveTar builds an outer tar (manifest + one layer.tar) like docker save.
func dockerSaveTar(t *testing.T, layerFiles map[string]string) string {
	t.Helper()
	layer := writeTar(t, layerFiles)
	outer := map[string]string{
		"manifest.json": `[{"Layers":["layer.tar"]}]`,
		"layer.tar":     string(layer),
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(path, writeTar(t, outer), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanImageFindsCryptoInLayers(t *testing.T) {
	img := dockerSaveTar(t, map[string]string{
		"app/main.py":     "import hashlib\nh = hashlib.md5()\n",
		"etc/secrets.env": "KEY=-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
	})

	findings, err := Scan([]string{img})
	if err != nil {
		t.Fatal(err)
	}

	algos := map[string]bool{}
	for _, f := range findings {
		algos[f.Asset.Algorithm] = true
		if !strings.Contains(f.Location.File, img+"::") {
			t.Errorf("location not image-relative: %q", f.Location.File)
		}
	}
	if !algos["MD5"] {
		t.Error("expected MD5 from app/main.py in the layer")
	}
	if !algos["private-key"] {
		t.Error("expected hardcoded private key from etc/id.pem in the layer")
	}
}

func TestExtractRejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	layer := writeTar(t, map[string]string{
		"../escape.txt": "pwned",
		"good.txt":      "ok",
	})
	tr, err := asTarReader(bytes.NewReader(layer))
	if err != nil || tr == nil {
		t.Fatalf("expected a tar reader, got tr=%v err=%v", tr, err)
	}
	var st extractStats
	if err := extractLayer(tr, root, &st); err != nil {
		t.Fatal(err)
	}

	// The traversal entry must not have been written above root.
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.txt")); err == nil {
		t.Fatal("path traversal escaped the extraction root")
	}
	if _, err := os.Stat(filepath.Join(root, "good.txt")); err != nil {
		t.Errorf("legitimate file was not extracted: %v", err)
	}
}

// `qryx image` on a container image it could not extract used to print one line
// on stderr, return no findings and no error, and let the CLI report a clean
// result with exit 0. Every layer of a Debian- or Ubuntu-based image is larger
// than the 32 MiB entry cap that produced exactly this failure, so the common
// case was an image that scanned as having no cryptography in it.
func TestScanReportsAnImageItCouldNotExtractAsAnError(t *testing.T) {
	// A layer tar cut in the middle of a file's data: the header parses, the
	// body ends early, and tar.Next reports the stream as unexpectedly over.
	layer := writeTar(t, map[string]string{"usr/bin/thing": strings.Repeat("x", 4096)})
	cut := string(layer[:1024])
	path := filepath.Join(t.TempDir(), "broken-image.tar")
	if err := os.WriteFile(path, writeTar(t, map[string]string{
		"manifest.json": `[{"Layers":["layer.tar"]}]`,
		"layer.tar":     cut,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan([]string{path})
	if err == nil {
		t.Fatalf("Scan returned nil error and %d finding(s) for an image it could not extract: a failed extraction reported as a clean image", len(findings))
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the image, so an operator scanning several cannot tell which one failed", err)
	}
}

// The cap that caused it. The seam exists so the test can drive a realistic
// image shape (a layer bigger than the per-file cap) with a few kilobytes
// instead of writing 32 MiB of zeroes in CI on every run.
func TestScanReadsALayerLargerThanTheFileCap(t *testing.T) {
	restore := maxFileBytes
	maxFileBytes = 512
	t.Cleanup(func() { maxFileBytes = restore })

	img := dockerSaveTar(t, map[string]string{
		"app/main.py": "import hashlib\nh = hashlib.md5()\n",
		"var/pad.bin": strings.Repeat("x", 4096), // pushes the layer past the cap
	})

	findings, err := Scan([]string{img})
	if err != nil {
		t.Fatalf("Scan returned %v for a layer larger than the per-file cap", err)
	}
	for _, f := range findings {
		if f.Asset.Algorithm == "MD5" {
			return
		}
	}
	t.Fatalf("no MD5 finding: the layer was truncated at the %d-byte cap and the image scanned clean", maxFileBytes)
}
