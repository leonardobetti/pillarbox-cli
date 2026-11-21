package archive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// buildTree creates a representative tree: nested files, an empty folder, a
// safe symlink and a long file name.
func buildTree(t *testing.T, root string) {
	t.Helper()
	write := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.txt", "alpha")
	write("sub/b.txt", "beta")
	write("sub/deep/c.txt", "gamma")
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("n", 250) + ".txt"
	write("sub/"+long, "long name content")
	if err := os.Symlink("a.txt", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
}

// treeHash maps every relative path to a type-tagged hash so two trees can be
// compared for identical structure and content.
func treeHash(t *testing.T, root string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		switch {
		case d.IsDir():
			m[filepath.ToSlash(rel)] = "dir"
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			m[filepath.ToSlash(rel)] = "symlink:" + target
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			m[filepath.ToSlash(rel)] = fmt.Sprintf("file:%x", sha256.Sum256(b))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	return m
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func makeTar(t *testing.T, entries func(tw *tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	entries(tw)
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

func addReg(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()
	hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o600}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader %s: %v", name, err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("Write %s: %v", name, err)
	}
}

func addDir(t *testing.T, tw *tar.Writer, name string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatalf("WriteHeader %s: %v", name, err)
	}
}

func addSymlink(t *testing.T, tw *tar.Writer, name, linkname string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: linkname, Mode: 0o777}); err != nil {
		t.Fatalf("WriteHeader %s: %v", name, err)
	}
}

func TestWriteExtractRoundTrip(t *testing.T) {
	src := t.TempDir()
	buildTree(t, src)

	var buf bytes.Buffer
	if err := NewWriter().WriteTree(&buf, src); err != nil {
		t.Fatalf("WriteTree: %v", err)
	}

	out := filepath.Join(t.TempDir(), "out")
	if err := NewExtractor().Extract(&buf, out, ExtractOptions{}); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	want := treeHash(t, src)
	got := treeHash(t, out)
	if !mapsEqual(want, got) {
		t.Fatalf("tree mismatch\nwant %v\ngot  %v", want, got)
	}
}

func TestExtractRejectsDotDot(t *testing.T) {
	dir := t.TempDir()
	data := makeTar(t, func(tw *tar.Writer) { addReg(t, tw, "../evil.txt", "evil") })
	err := NewExtractor().Extract(bytes.NewReader(data), dir, ExtractOptions{})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v, want ErrUnsafePath", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "..", "evil.txt")); statErr == nil {
		t.Fatal("file written outside the target")
	}
}

func TestExtractRejectsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	data := makeTar(t, func(tw *tar.Writer) { addReg(t, tw, "/tmp/pillarbox-abs-evil.txt", "evil") })
	err := NewExtractor().Extract(bytes.NewReader(data), dir, ExtractOptions{})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v, want ErrUnsafePath", err)
	}
	if _, statErr := os.Stat("/tmp/pillarbox-abs-evil.txt"); statErr == nil {
		t.Fatal("file written at absolute path")
	}
}

func TestExtractRejectsSymlinkOutsideTarget(t *testing.T) {
	dir := t.TempDir()
	for _, link := range []string{"../../etc", "/etc", ".."} {
		data := makeTar(t, func(tw *tar.Writer) { addSymlink(t, tw, "esc", link) })
		err := NewExtractor().Extract(bytes.NewReader(data), dir, ExtractOptions{})
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("link %q: err = %v, want ErrUnsafePath", link, err)
		}
		if _, statErr := os.Lstat(filepath.Join(dir, "esc")); statErr == nil {
			t.Fatalf("escaping symlink %q was created", link)
		}
	}
}

func TestExtractRejectsWriteThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	// d/ln points at .. (the target root, lexically inside), but writing
	// d/ln/x through the symlink must still be rejected.
	data := makeTar(t, func(tw *tar.Writer) {
		addDir(t, tw, "d")
		addSymlink(t, tw, "d/ln", "..")
		addReg(t, tw, "d/ln/x", "evil")
	})
	err := NewExtractor().Extract(bytes.NewReader(data), dir, ExtractOptions{})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v, want ErrUnsafePath", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "x")); statErr == nil {
		t.Fatal("file written through a symlink")
	}
}

func TestLongNamesRoundTrip(t *testing.T) {
	src := t.TempDir()
	long := strings.Repeat("d", 120) + "/" + strings.Repeat("n", 250) + ".txt"
	p := filepath.Join(src, filepath.FromSlash(long))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("deep long"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewWriter().WriteTree(&buf, src); err != nil {
		t.Fatalf("WriteTree: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := NewExtractor().Extract(&buf, out, ExtractOptions{}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !mapsEqual(treeHash(t, src), treeHash(t, out)) {
		t.Fatal("long-name tree mismatch")
	}
}

func TestEmptyFolderRoundTrip(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewWriter().WriteTree(&buf, src); err != nil {
		t.Fatalf("WriteTree: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := NewExtractor().Extract(&buf, out, ExtractOptions{}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	info, err := os.Stat(filepath.Join(out, "empty"))
	if err != nil {
		t.Fatalf("empty folder missing after extract: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("empty entry is not a directory")
	}
	entries, err := os.ReadDir(filepath.Join(out, "empty"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty folder has %d entries", len(entries))
	}
}

func TestExtractRefusesOverwriteWithoutForce(t *testing.T) {
	src := t.TempDir()
	buildTree(t, src)
	var buf bytes.Buffer
	if err := NewWriter().WriteTree(&buf, src); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "out")
	if err := NewExtractor().Extract(bytes.NewReader(buf.Bytes()), out, ExtractOptions{}); err != nil {
		t.Fatalf("first Extract: %v", err)
	}
	err := NewExtractor().Extract(bytes.NewReader(buf.Bytes()), out, ExtractOptions{})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second Extract without Force: err = %v, want ErrExists", err)
	}
	if err := NewExtractor().Extract(bytes.NewReader(buf.Bytes()), out, ExtractOptions{Force: true}); err != nil {
		t.Fatalf("Extract with Force: %v", err)
	}
}

func TestExtractRejectsDeviceEntry(t *testing.T) {
	dir := t.TempDir()
	data := makeTar(t, func(tw *tar.Writer) {
		if err := tw.WriteHeader(&tar.Header{Name: "dev", Typeflag: tar.TypeChar, Mode: 0o600}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
	})
	err := NewExtractor().Extract(bytes.NewReader(data), dir, ExtractOptions{})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v, want ErrUnsafePath", err)
	}
}

func TestWriteTreeRejectsUnsupportedType(t *testing.T) {
	src := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(src, "pipe"), 0o600); err != nil {
		t.Skipf("cannot create fifo: %v", err)
	}
	var buf bytes.Buffer
	if err := NewWriter().WriteTree(&buf, src); err == nil {
		t.Fatal("WriteTree on a fifo succeeded, want error")
	}
}

// Ensure the tar stream itself carries no absolute or .. names.
func TestWriterEmitsRelativeNamesOnly(t *testing.T) {
	src := t.TempDir()
	buildTree(t, src)
	var buf bytes.Buffer
	if err := NewWriter().WriteTree(&buf, src); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if filepath.IsAbs(filepath.FromSlash(hdr.Name)) || strings.HasPrefix(filepath.Clean(filepath.FromSlash(hdr.Name)), "..") {
			t.Fatalf("non-relative entry name %q", hdr.Name)
		}
	}
}
