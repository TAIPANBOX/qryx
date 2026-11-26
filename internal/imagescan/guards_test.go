package imagescan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name, body, link string
	typ              byte
}

// tarOf builds a tar in the order given, with any entry type, which the map
// based writeTar cannot express (links, and an order that matters).
func tarOf(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Typeflag: typ, Name: e.name, Linkname: e.link, Mode: 0o644}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func extract(t *testing.T, layer []byte) (string, extractStats, error) {
	t.Helper()
	root := t.TempDir()
	tr, err := asTarReader(bytes.NewReader(layer))
	if err != nil || tr == nil {
		t.Fatalf("expected a layer, got tr=%v err=%v", tr, err)
	}
	var st extractStats
	err = extractLayer(tr, root, &st)
	return root, st, err
}

// Invariant 7: a link in a layer is never created, so a later entry written
// "through" it lands inside the extraction root, not where the link points.
// The tool unpacks images it did not build; a layer that plants
// `etc -> /` and then writes `etc/cron.d/x` must not reach the host.
func TestExtractNeverCreatesOrFollowsLinks(t *testing.T) {
	outside := t.TempDir()
	root, _, err := extract(t, tarOf(t,
		entry{name: "escape", typ: tar.TypeSymlink, link: outside},
		entry{name: "hard", typ: tar.TypeLink, link: "/etc/passwd"},
		entry{name: "escape/planted.txt", body: "pwned"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "planted.txt")); err == nil {
		t.Fatal("a file was written through a symlink out of the extraction root")
	}
	fi, err := os.Lstat(filepath.Join(root, "escape"))
	if err != nil {
		t.Fatalf("the entry under the link name was not extracted inside root: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("a symlink from the layer was created")
	}
	if _, err := os.Lstat(filepath.Join(root, "hard")); err == nil {
		t.Fatal("a hard link from the layer was created")
	}
	if got, _ := os.ReadFile(filepath.Join(root, "escape", "planted.txt")); string(got) != "pwned" {
		t.Errorf("the regular file was not extracted inside root: %q", got)
	}
}

// Invariant 7: the tar-bomb budget is per image and cumulative. Files that fit
// one at a time still stop extraction once their total passes the cap.
func TestExtractStopsAtTheTotalBudget(t *testing.T) {
	restore := maxTotalBytes
	maxTotalBytes = 1000
	t.Cleanup(func() { maxTotalBytes = restore })

	chunk := strings.Repeat("x", 600)
	if _, st, err := extract(t, tarOf(t, entry{name: "a", body: chunk})); err != nil || st.written != 600 {
		t.Fatalf("one file under the budget: written %d, err %v", st.written, err)
	}
	if _, st, err := extract(t, tarOf(t, entry{name: "a", body: chunk[:500]}, entry{name: "b", body: chunk[:500]})); err != nil || st.written != 1000 {
		t.Fatalf("exactly the budget is allowed: written %d, err %v", st.written, err)
	}
	_, _, err := extract(t, tarOf(t, entry{name: "a", body: chunk}, entry{name: "b", body: chunk}))
	if err == nil || !strings.Contains(err.Error(), "1000-byte extraction limit") {
		t.Fatalf("two files past the budget: got %v, want the extraction limit error", err)
	}
}

// An OCI whiteout marker is a deletion record, not a file, and is not
// extracted; an absolute name is anchored inside root rather than refused.
func TestExtractSkipsWhiteoutsAndAnchorsAbsoluteNames(t *testing.T) {
	root, _, err := extract(t, tarOf(t,
		entry{name: "app/.wh.secret.py", body: "import hashlib\nhashlib.md5()\n"},
		entry{name: "/abs/file.txt", body: "ok"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "app", ".wh.secret.py")); err == nil {
		t.Error("a whiteout marker was extracted as a file")
	}
	if _, err := os.Stat(filepath.Join(root, "abs", "file.txt")); err != nil {
		t.Errorf("an absolute name was not anchored inside root: %v", err)
	}
	for _, name := range []string{"../x", "a/../../x", "/../x"} {
		if dest, ok := safeJoin(root, name); !ok || !strings.HasPrefix(dest, root+string(filepath.Separator)) {
			t.Errorf("safeJoin(%q) = %q, %v: want a path inside root", name, dest, ok)
		}
	}
}

// docker save writes plain layers, but OCI layouts gzip them: a gzipped layer
// is recognized and scanned, and an entry that only looks gzipped is skipped
// rather than ending the scan.
func TestScanReadsGzippedLayersAndSkipsCorruptOnes(t *testing.T) {
	layer := tarOf(t, entry{name: "app/main.py", body: "import hashlib\nh = hashlib.md5()\n"})
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(layer); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(t.TempDir(), "oci.tar")
	if err := os.WriteFile(img, tarOf(t,
		entry{name: "blobs/bogus", body: "\x1f\x8bnot really gzip"},
		entry{name: "blobs/layer", body: gz.String()},
	), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan([]string{img})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Asset.Algorithm == "MD5" && f.Location.File == img+"::app/main.py" {
			found = true
		}
	}
	if !found {
		t.Errorf("MD5 in a gzipped layer was not found: %+v", findings)
	}

	if _, err := Scan([]string{filepath.Join(t.TempDir(), "missing.tar")}); err == nil {
		t.Error("a missing image must be an error")
	}
}
