package keystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

func sampleKeystore() *Keystore {
	return &Keystore{
		Version:   1,
		Mode:      ModePassword,
		Argon2:    DefaultArgon2Params,
		Salt:      bytes.Repeat([]byte{0x01}, 16),
		Recipient: "age1ql3z7hjy54pw3hyww5ayyfgfgkgle3x8mnhc5juga2sgjj7p2t5qqvfafg2",
		WrappedIdentity: WrappedKey{
			Nonce:      bytes.Repeat([]byte{0x02}, 24),
			Ciphertext: []byte("ciphertext"),
		},
		CreatedAt: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
	}
}

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "pillarbox", "keystore.json"))

	ok, err := s.Exists()
	if err != nil || ok {
		t.Fatalf("Exists before save = %v, %v", ok, err)
	}

	want := sampleKeystore()
	if err := s.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("keystore mode = %o, want 600", info.Mode().Perm())
	}

	ok, err = s.Exists()
	if err != nil || !ok {
		t.Fatalf("Exists after save = %v, %v", ok, err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded keystore differs\nwant %+v\ngot  %+v", *want, *got)
	}

	// No temp files left behind, PRD 7.1 step 6.
	entries, err := os.ReadDir(filepath.Dir(s.Path()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".keystore-tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestStoreLoadNotFound(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "keystore.json"))
	_, err := s.Load()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestStoreLoadInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(path).Load()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestStoreLoadRejectsOpenPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	data, err := json.Marshal(sampleKeystore())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = NewStore(path).Load()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid for mode 0644", err)
	}
}

func TestStoreLoadRejectsBadFields(t *testing.T) {
	ks := sampleKeystore()
	ks.Recipient = ""
	path := filepath.Join(t.TempDir(), "keystore.json")
	if err := os.WriteFile(path, mustJSON(t, ks), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(path).Load()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid for missing recipient", err)
	}
}

func TestSaveRejectsInvalidKeystore(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "keystore.json"))
	ks := sampleKeystore()
	ks.Mode = Mode("bogus")
	if err := s.Save(ks); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestWrapperRoundTrip(t *testing.T) {
	ks := sampleKeystore()
	kek := bytes.Repeat([]byte{0x09}, 32)
	w := NewWrapper()

	wk, err := w.Wrap(kek, ks, []byte("AGE-SECRET-KEY-1..."))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(wk.Nonce) != 24 {
		t.Fatalf("nonce len = %d, want 24", len(wk.Nonce))
	}
	got, err := w.Unwrap(kek, ks, wk)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1..." {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestWrapperWrongKEK(t *testing.T) {
	ks := sampleKeystore()
	w := NewWrapper()
	wk, err := w.Wrap(bytes.Repeat([]byte{0x09}, 32), ks, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Unwrap(bytes.Repeat([]byte{0x0A}, 32), ks, wk); err == nil {
		t.Fatal("Unwrap with wrong KEK succeeded")
	}
}

func TestWrapperTamperedCiphertext(t *testing.T) {
	ks := sampleKeystore()
	kek := bytes.Repeat([]byte{0x09}, 32)
	w := NewWrapper()
	wk, err := w.Wrap(kek, ks, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	wk.Ciphertext[0] ^= 0x01
	if _, err := w.Unwrap(kek, ks, wk); err == nil {
		t.Fatal("Unwrap of tampered ciphertext succeeded")
	}
}

func TestWrapperAADBindsToKeystore(t *testing.T) {
	kek := bytes.Repeat([]byte{0x09}, 32)
	w := NewWrapper()
	ks := sampleKeystore()
	wk, err := w.Wrap(kek, ks, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	other := sampleKeystore()
	other.Recipient = "age1other"
	if _, err := w.Unwrap(kek, other, wk); err == nil {
		t.Fatal("Unwrap under a different recipient succeeded; AAD not bound")
	}
}

func TestModeHelpers(t *testing.T) {
	cases := []struct {
		m       Mode
		valid   bool
		has2fa  bool
		hasDev  bool
		summary string
	}{
		{ModePassword, true, false, false, "This file needs a passphrase."},
		{ModePIN, true, false, true, "This file needs a PIN on this machine (or the recovery key)."},
		{ModePassword2FA, true, true, false, "This file needs a passphrase and a 2FA code."},
		{ModePIN2FA, true, true, true, "This file needs a PIN on this machine and a 2FA code (or the recovery key)."},
		{Mode("bogus"), false, false, false, "This file needs unlock credentials."},
	}
	for _, c := range cases {
		if c.m.Valid() != c.valid || c.m.Has2FA() != c.has2fa || c.m.HasDeviceSecret() != c.hasDev {
			t.Fatalf("mode %q: got valid=%v 2fa=%v dev=%v", c.m, c.m.Valid(), c.m.Has2FA(), c.m.HasDeviceSecret())
		}
		if got := c.m.NeedsSummary(); got != c.summary {
			t.Fatalf("mode %q NeedsSummary = %q, want %q", c.m, got, c.summary)
		}
	}
	msg := FormatEncryptSuccess("/tmp/a.txt.pbx", ModePIN, false, "AGE-SECRET-KEY-1TEST")
	for _, want := range []string{
		"Done. File encrypted successfully.",
		"Saved at: /tmp/a.txt.pbx",
		"original file is still in the folder",
		"encrypted using a PIN",
		"AGE-SECRET-KEY-1TEST",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("encrypt success missing %q in %q", want, msg)
		}
	}
	dec := FormatDecryptSuccess("/tmp/a.txt")
	if !strings.Contains(dec, "Done. File decrypted successfully.") || !strings.Contains(dec, "Saved at: /tmp/a.txt") {
		t.Fatalf("decrypt success = %q", dec)
	}
}
