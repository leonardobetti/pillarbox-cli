package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTOTPSeedStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "totp.seed")
	store := NewTOTPSeedStore(path)

	ok, err := store.Exists()
	if err != nil || ok {
		t.Fatalf("Exists = %v, %v; want false, nil", ok, err)
	}

	seed := bytes.Repeat([]byte{0xab}, 20)
	if err := store.Save(seed); err != nil {
		t.Fatal(err)
	}
	ok, err = store.Exists()
	if err != nil || !ok {
		t.Fatalf("Exists after Save = %v, %v", ok, err)
	}
	got, err := store.Load()
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("Load = %v, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("permissions = %v, %v", info.Mode(), err)
	}
}

func TestTOTPSeedStoreRejectsBadLength(t *testing.T) {
	store := NewTOTPSeedStore(filepath.Join(t.TempDir(), "totp.seed"))
	if err := store.Save([]byte("short")); err == nil {
		t.Fatal("expected length error")
	}
}
