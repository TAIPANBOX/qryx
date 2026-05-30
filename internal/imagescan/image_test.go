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
	tr, err := asTarReader(layer)
	if err != nil || tr == nil {
		t.Fatalf("expected a tar reader, got tr=%v err=%v", tr, err)
	}
	var total int64
	if err := extractLayer(tr, root, &total); err != nil {
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
