package vault

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildFolderTree creates a representative folder: nested files, an empty
// folder, a safe symlink and a long name.
func buildFolderTree(t *testing.T, root string) {
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
	write("sub/"+strings.Repeat("n", 250)+".txt", "long name")
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
}

// treeChecksums maps every relative path to a type-tagged sha256 so a folder
// round trip can be compared for identical structure and content.
func treeChecksums(t *testing.T, root string) map[string]string {
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

func TestFolderRoundTrip(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "project")
	buildFolderTree(t, src)

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock folder: %v", err)
	}
	if dst != src+tarPbxExt {
		t.Fatalf("default folder output = %q, want %q", dst, src+tarPbxExt)
	}

	// FR-04: no plaintext names in the .tar.pbx.
	pbx, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"a.txt", "sub", "b.txt", "project"} {
		if bytes.Contains(pbx, []byte(leak)) {
			t.Fatalf("plaintext name %q leaked into %s", leak, dst)
		}
	}

	out := filepath.Join(base, "restored")
	got, err := v.Unlock(dst, id, UnlockOptions{Out: out})
	if err != nil {
		t.Fatalf("Unlock folder: %v", err)
	}
	if got != out {
		t.Fatalf("Unlock returned %q, want %q", got, out)
	}

	want := treeChecksums(t, src)
	have := treeChecksums(t, out)
	if len(want) != len(have) {
		t.Fatalf("checksum count differs: want %d got %d\nwant %v\ngot %v", len(want), len(have), want, have)
	}
	for k, v := range want {
		if have[k] != v {
			t.Fatalf("entry %q: want %q got %q", k, v, have[k])
		}
	}

	// The input tree is unchanged, FR-03.
	if !mapsEqualTree(treeChecksums(t, src), want) {
		t.Fatal("lock modified the input folder")
	}
	requireNoPartialOutput(t, base, src, dst, out)
}

func mapsEqualTree(a, b map[string]string) bool {
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

func TestFolderDefaultUnlockName(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "project")
	buildFolderTree(t, src)

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	want := treeChecksums(t, src)
	if err := os.RemoveAll(src); err != nil {
		t.Fatal(err)
	}
	got, err := v.Unlock(dst, id, UnlockOptions{})
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got != src {
		t.Fatalf("default folder unlock output = %q, want %q", got, src)
	}
	if !mapsEqualTree(treeChecksums(t, src), want) {
		t.Fatal("restored folder checksums differ")
	}
}

func TestUnlockFolderTampered(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "project")
	buildFolderTree(t, src)

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	bad := tamper(t, dst, func(b []byte) []byte {
		b[len(b)/2] ^= 0x01
		return b
	})
	out := filepath.Join(base, "out")
	_, err = v.Unlock(bad, id, UnlockOptions{Out: out})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered folder: err = %v, want ErrIntegrity", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("partial folder output left behind")
	}
	requireNoPartialOutput(t, base, src, dst, bad)
}

func TestUnlockFolderWrongIdentity(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "project")
	buildFolderTree(t, src)

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	out := filepath.Join(base, "out")
	_, err = v.Unlock(dst, newIdentity(t), UnlockOptions{Out: out})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong identity: err = %v, want ErrIntegrity", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("partial folder output left behind")
	}
}

func TestFolderEmptySubfolderRoundTrip(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "project")
	if err := os.MkdirAll(filepath.Join(src, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	out := filepath.Join(base, "out")
	if _, err := v.Unlock(dst, id, UnlockOptions{Out: out}); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	info, err := os.Stat(filepath.Join(out, "empty"))
	if err != nil || !info.IsDir() {
		t.Fatalf("empty subfolder missing after round trip: %v", err)
	}
}
