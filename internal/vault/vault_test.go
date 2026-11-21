package vault

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	return id
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return b
}

// requireNoPartialOutput fails if any temp file or unexpected output file is
// left in dir, PRD 7.3 step 3 and 7.4 step 4.
func requireNoPartialOutput(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
		if strings.HasPrefix(e.Name(), ".pillarbox-tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	for _, w := range want {
		if !got[filepath.Base(w)] {
			t.Fatalf("expected file missing: %s", w)
		}
	}
	for name := range got {
		found := false
		for _, w := range want {
			if name == filepath.Base(w) {
				found = true
			}
		}
		if !found {
			t.Fatalf("unexpected file left behind: %s", name)
		}
	}
}

func TestLockUnlockRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	content := []byte("attack at dawn\n")
	writeFile(t, src, content)

	v := New()
	id := newIdentity(t)

	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if dst != src+pbxExt {
		t.Fatalf("default output = %q, want %q", dst, src+pbxExt)
	}

	out := filepath.Join(dir, "restored.txt")
	got, err := v.Unlock(dst, id, UnlockOptions{Out: out})
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got != out {
		t.Fatalf("Unlock returned %q, want %q", got, out)
	}
	if !bytes.Equal(readFile(t, out), content) {
		t.Fatal("restored content differs from original")
	}
	// FR-03: the input is unchanged.
	if !bytes.Equal(readFile(t, src), content) {
		t.Fatal("lock modified the input file")
	}
	requireNoPartialOutput(t, dir, src, dst, out)
}

func TestUnlockWrongIdentity(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	writeFile(t, src, []byte("top secret"))

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	out := filepath.Join(dir, "out.txt")
	_, err = v.Unlock(dst, newIdentity(t), UnlockOptions{Out: out})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Unlock with wrong identity: err = %v, want ErrIntegrity", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("partial output left behind after wrong identity")
	}
	requireNoPartialOutput(t, dir, src, dst)
}

// tamper returns a copy of the .pbx file with one modification applied.
func tamper(t *testing.T, dst string, fn func([]byte) []byte) string {
	t.Helper()
	data := readFile(t, dst)
	out := filepath.Join(filepath.Dir(dst), "tampered.pbx")
	writeFile(t, out, fn(data))
	return out
}

func TestUnlockFlippedByte(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	writeFile(t, src, bytes.Repeat([]byte("x"), 4096))

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
	_, err = v.Unlock(bad, id, UnlockOptions{})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("flipped byte: err = %v, want ErrIntegrity", err)
	}
	requireNoPartialOutput(t, dir, src, dst, bad)
}

func TestUnlockTruncated(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	writeFile(t, src, bytes.Repeat([]byte("y"), 4096))

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	bad := tamper(t, dst, func(b []byte) []byte { return b[:len(b)-10] })
	_, err = v.Unlock(bad, id, UnlockOptions{})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("truncated: err = %v, want ErrIntegrity", err)
	}
	requireNoPartialOutput(t, dir, src, dst, bad)
}

func TestUnlockAppendedByte(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	writeFile(t, src, bytes.Repeat([]byte("z"), 4096))

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	bad := tamper(t, dst, func(b []byte) []byte { return append(b, 0x00) })
	_, err = v.Unlock(bad, id, UnlockOptions{})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("appended byte: err = %v, want ErrIntegrity", err)
	}
	requireNoPartialOutput(t, dir, src, dst, bad)
}

func TestLockUnlockEmptyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "empty.txt")
	writeFile(t, src, nil)

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock empty: %v", err)
	}
	out := filepath.Join(dir, "empty.out")
	if _, err := v.Unlock(dst, id, UnlockOptions{Out: out}); err != nil {
		t.Fatalf("Unlock empty: %v", err)
	}
	if got := readFile(t, out); len(got) != 0 {
		t.Fatalf("restored empty file has %d bytes", len(got))
	}
}

func TestLockRefusesExistingOutputWithoutForce(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, []byte("data"))

	v := New()
	id := newIdentity(t)
	if _, err := v.Lock(src, id.Recipient().String(), LockOptions{}); err != nil {
		t.Fatalf("first Lock: %v", err)
	}
	if _, err := v.Lock(src, id.Recipient().String(), LockOptions{}); err == nil {
		t.Fatal("second Lock without Force succeeded, want error")
	}
	if _, err := v.Lock(src, id.Recipient().String(), LockOptions{Force: true}); err != nil {
		t.Fatalf("Lock with Force: %v", err)
	}
}

func TestUnlockRefusesExistingOutputWithoutForce(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, []byte("data"))

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	out := strings.TrimSuffix(dst, pbxExt)
	writeFile(t, out, []byte("pre-existing"))
	if _, err := v.Unlock(dst, id, UnlockOptions{}); err == nil {
		t.Fatal("Unlock over existing output without Force succeeded, want error")
	}
	if got := readFile(t, out); string(got) != "pre-existing" {
		t.Fatal("existing output was overwritten without Force")
	}
	if _, err := v.Unlock(dst, id, UnlockOptions{Force: true}); err != nil {
		t.Fatalf("Unlock with Force: %v", err)
	}
	if got := readFile(t, out); string(got) != "data" {
		t.Fatalf("output = %q, want %q", got, "data")
	}
}

func TestLockCustomOutput(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, []byte("data"))

	v := New()
	id := newIdentity(t)
	custom := filepath.Join(dir, "custom.enc")
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{Out: custom})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if dst != custom {
		t.Fatalf("dst = %q, want %q", dst, custom)
	}
}

func TestLockRemoveOriginal(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	writeFile(t, src, []byte("data"))

	v := New()
	id := newIdentity(t)
	if _, err := v.Lock(src, id.Recipient().String(), LockOptions{RemoveOriginal: true}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("RemoveOriginal did not remove the source")
	}
}

func TestUnlockDefaultNameStripsPbx(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "note.txt")
	writeFile(t, src, []byte("hello"))

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	// Remove the source so the default output name is free.
	if err := os.Remove(src); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, err := v.Unlock(dst, id, UnlockOptions{})
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got != src {
		t.Fatalf("default unlock output = %q, want %q", got, src)
	}
	if !bytes.Equal(readFile(t, src), []byte("hello")) {
		t.Fatal("restored content differs")
	}
}

// TestStockAgeBinaryDecrypts proves FR-12-style interop: a file locked by this
// code decrypts with the stock age binary and the identity. Skipped when the
// age binary is not on PATH.
func TestStockAgeBinaryDecrypts(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("stock age binary not on PATH")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "interop.txt")
	content := []byte("locked by pillarbox, opened by stock age\n")
	writeFile(t, src, content)

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	keyFile := filepath.Join(dir, "key.txt")
	writeFile(t, keyFile, []byte(id.String()+"\n"))
	out := filepath.Join(dir, "interop.out")
	cmd := exec.Command("age", "-d", "-i", keyFile, "-o", out, dst)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stock age -d failed: %v\n%s", err, combined)
	}
	if !bytes.Equal(readFile(t, out), content) {
		t.Fatal("stock age output differs from original")
	}
}

// TestUnlockFileOutputDirMissingIsNotIntegrity guards the exit-code
// contract of PRD section 9: an infrastructure failure (here, a temp file
// that cannot be created because the output directory does not exist) must
// not be reported as ErrIntegrity, which cli maps to exit code 4.
func TestUnlockFileOutputDirMissingIsNotIntegrity(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	writeFile(t, src, []byte("data\n"))

	v := New()
	id := newIdentity(t)
	dst, err := v.Lock(src, id.Recipient().String(), LockOptions{})
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}

	out := filepath.Join(dir, "no-such-dir", "out")
	_, err = v.Unlock(dst, id, UnlockOptions{Out: out})
	if err == nil {
		t.Fatal("Unlock into missing directory: want error, got nil")
	}
	if errors.Is(err, ErrIntegrity) {
		t.Fatalf("infrastructure error misclassified as integrity: %v", err)
	}
}
