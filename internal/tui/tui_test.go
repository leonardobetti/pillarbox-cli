package tui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"github.com/leonardobetti/pillarbox-cli/internal/auth"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
	"github.com/leonardobetti/pillarbox-cli/internal/vault"
)

// fakeTOTP accepts 123456 at a fixed step, so 2FA flows are deterministic.
type fakeTOTP struct{}

const fakeStep = int64(1000000)

func (f *fakeTOTP) GenerateSeed() ([]byte, string, error) {
	return bytes.Repeat([]byte{0x42}, 20), "otpauth://totp/pillarbox?secret=FAKE", nil
}

func (f *fakeTOTP) Verify(seed []byte, code string, lastStep int64) (bool, int64, error) {
	if code == "123456" && lastStep != fakeStep {
		return true, fakeStep, nil
	}
	return false, 0, nil
}

func testDeps(t *testing.T) *Deps {
	t.Helper()
	dir := t.TempDir()
	return &Deps{
		Settings: keystore.NewSettingsStore(filepath.Join(dir, "cfg", "settings.json")),
		Wrapper:  keystore.NewWrapper(),
		KDF:      auth.NewKDF(),
		TOTP:     &fakeTOTP{},
		DevStore: auth.NewDeviceSecretStore(filepath.Join(dir, "cfg", "device.key")),
		Vault:    vault.New(),
		Version:  "0.1.0-test",
		StartDir: dir,
	}
}

func setupSettings(t *testing.T, d *Deps, mode keystore.Mode) {
	t.Helper()
	if err := d.Settings.Save(&keystore.Settings{KeyType: mode}); err != nil {
		t.Fatal(err)
	}
}

func key(t tea.KeyType) tea.Msg { return tea.KeyMsg{Type: t} }

// acc accumulates everything the program has printed. teatest.WaitFor
// consumes the shared output stream, so each wait must append to acc and
// check the whole history, not just newly arrived bytes.
type acc struct{ b []byte }

func waitFor(t *testing.T, tm *teatest.TestModel, a *acc, substrs ...string) {
	t.Helper()
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		a.b = append(a.b, b...)
		for _, s := range substrs {
			if !bytes.Contains(a.b, []byte(s)) {
				return false
			}
		}
		return true
	}, teatest.WithDuration(10*time.Second))
}

// pickATxt moves past the parent-directory row (and cfg/ when present) onto a.txt.
func pickATxt(tm *teatest.TestModel, hasCfg bool) {
	tm.Send(key(tea.KeyDown)) // parent -> first entry
	if hasCfg {
		tm.Send(key(tea.KeyDown)) // cfg/ -> a.txt
	}
	tm.Send(key(tea.KeyEnter))
}

// pickPBX selects a.txt.pbx: parent, cfg/, a.txt, a.txt.pbx.
func pickPBX(tm *teatest.TestModel) {
	tm.Send(key(tea.KeyDown)) // parent -> cfg/
	tm.Send(key(tea.KeyDown)) // cfg/ -> a.txt
	tm.Send(key(tea.KeyDown)) // a.txt -> a.txt.pbx
	tm.Send(key(tea.KeyEnter))
}

func TestHomeLayoutShowsProposalChrome(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Pillarbox", tagline,
		"Encrypt", "Decrypt", "Status", "Settings", "Help",
		"Select a file to encrypt",
		"Tab, ← or → to navigate", "Enter to select", "Q to quit")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)
}

func TestHomeMenuTabNavigation(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)
	if err := os.WriteFile(filepath.Join(deps.StartDir, "a.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Select a file to encrypt")

	tm.Send(tea.KeyMsg{Type: tea.KeyTab}) // -> Decrypt
	waitFor(t, tm, a, "Select a .pbx file to decrypt")

	tm.Send(tea.KeyMsg{Type: tea.KeyShiftTab}) // -> Encrypt
	waitFor(t, tm, a, "Select a file to encrypt")

	tm.Send(key(tea.KeyRight)) // -> Decrypt via arrow
	waitFor(t, tm, a, "Select a .pbx file to decrypt")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)
}

func TestHomeEncryptFileWithOwnKey(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)
	if err := os.WriteFile(filepath.Join(deps.StartDir, "a.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Select a file to encrypt", "a.txt")
	pickATxt(tm, true)
	waitFor(t, tm, a, "Secret (password)", "at least 12 characters")
	tm.Type("correct horse battery staple")
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, ".pbx")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)

	pbx := filepath.Join(deps.StartDir, "a.txt.pbx")
	if _, err := os.Stat(pbx); err != nil {
		t.Fatalf("no .pbx output: %v", err)
	}
	ks, err := vault.New().ReadKey(pbx)
	if err != nil {
		t.Fatalf("no embedded key in .pbx: %v", err)
	}
	if ks.Mode != keystore.ModePassword {
		t.Fatalf("embedded key mode = %q, want password", ks.Mode)
	}
	if _, err := os.Stat(pbx + ".key"); !os.IsNotExist(err) {
		t.Fatal("sidecar .key file should not exist anymore")
	}
}

func TestHomeEncryptAsksKeyTypeWhenUnset(t *testing.T) {
	deps := testDeps(t) // no settings: key type unset
	if err := os.WriteFile(filepath.Join(deps.StartDir, "a.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Select a file to encrypt", "a.txt")
	pickATxt(tm, false)
	waitFor(t, tm, a, "Key type not set", "pin")
	tm.Send(key(tea.KeyDown))  // -> pin
	tm.Send(key(tea.KeyEnter)) // choose pin -> secret screen
	waitFor(t, tm, a, "Secret (pin)", "6 to 12 digits")
	tm.Type("123456")
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, ".pbx")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)

	ks, err := vault.New().ReadKey(filepath.Join(deps.StartDir, "a.txt.pbx"))
	if err != nil {
		t.Fatal(err)
	}
	if ks.Mode != keystore.ModePIN {
		t.Fatalf("sidecar mode = %q, want pin", ks.Mode)
	}
	st, err := deps.Settings.Load()
	if err != nil || st.KeyType != keystore.ModePIN {
		t.Fatalf("key type not persisted: %v, %+v", err, st)
	}
}

func TestPickerHidesDotfiles(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)
	for _, name := range []string{".secret", "a.txt"} {
		if err := os.WriteFile(filepath.Join(deps.StartDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(deps.StartDir, ".hiddendir"), 0o700); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Select a file to encrypt", "a.txt")
	if bytes.Contains(a.b, []byte(".secret")) || bytes.Contains(a.b, []byte(".hiddendir")) {
		t.Fatal("picker shows dotfiles")
	}

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)
}

func TestHomeDecryptOverwritesOriginal(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)
	src := filepath.Join(deps.StartDir, "a.txt")
	if err := os.WriteFile(src, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Select a file to encrypt", "a.txt")
	pickATxt(tm, true)
	waitFor(t, tm, a, "Secret (password)")
	tm.Type("correct horse battery staple")
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, ".pbx")

	if err := os.WriteFile(src, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Any key on the result screen returns to the Encrypt tab; then switch.
	// Use a fresh accumulator so "Secret (password)" from encrypt does not
	// satisfy the decrypt wait immediately.
	tm.Send(key(tea.KeyEnter))
	a2 := &acc{}
	waitFor(t, tm, a2, "Select a file to encrypt")
	tm.Send(tea.KeyMsg{Type: tea.KeyTab}) // -> Decrypt
	waitFor(t, tm, a2, "Select a .pbx file to decrypt")
	pickPBX(tm)
	waitFor(t, tm, a2, "Secret (password)")
	tm.Type("correct horse battery staple")
	tm.Send(key(tea.KeyEnter))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(src); err == nil && string(b) == "original" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)

	b, err := os.ReadFile(src)
	if err != nil || string(b) != "original" {
		t.Fatalf("original not restored: %q, %v", b, err)
	}
}

func TestTwofaViewFits24Lines(t *testing.T) {
	deps := testDeps(t)
	p := newTwofaPrompt(deps, bytes.Repeat([]byte{0x42}, 20),
		"otpauth://totp/pillarbox?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=pillarbox")
	v := p.View()
	lines := strings.Split(v, "\n")
	if len(lines) > 24 {
		t.Fatalf("2FA view is %d lines, want <= 24", len(lines))
	}
	if !strings.Contains(v, "6-digit code") || !strings.Contains(v, "enter continue") {
		t.Fatal("2FA view lost the code entry or the footer")
	}
}

func TestHomeEncryptAuthGate(t *testing.T) {
	deps := testDeps(t)
	if err := deps.Settings.Save(&keystore.Settings{KeyType: keystore.ModePassword, AuthEncrypt: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deps.StartDir, "a.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	// Auth-encrypt on: opening Encrypt asks for the secret before the picker.
	waitFor(t, tm, a, "Secret (password)")
	tm.Type("correct horse battery staple")
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, "Select a file to encrypt", "a.txt")
	pickATxt(tm, true)
	waitFor(t, tm, a, ".pbx")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)

	if _, err := os.Stat(filepath.Join(deps.StartDir, "a.txt.pbx")); err != nil {
		t.Fatalf("no .pbx output: %v", err)
	}
}

func TestHomeSettingsStableNavigation(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Select a file to encrypt")
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyTab}) // Encrypt -> Decrypt -> Status -> Settings
	}
	waitFor(t, tm, a, "Key type:", "Require authentication to encrypt: no", "a apply")

	tm.Send(tea.KeyMsg{Type: tea.KeyTab})       // cursor -> auth-encrypt
	tm.Send(tea.KeyMsg{Type: tea.KeyBackspace}) // wrap back to key type
	tm.Send(key(tea.KeyDown))                   // cursor -> auth-encrypt
	tm.Send(key(tea.KeyLeft))                   // toggle to yes
	waitFor(t, tm, a, "Require authentication to encrypt: yes")
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")}) // apply

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := deps.Settings.Load(); err == nil && st.AuthEncrypt {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, err := deps.Settings.Load()
	if err != nil || !st.AuthEncrypt {
		t.Fatalf("auth-encrypt not persisted: %v, %+v", err, st)
	}
	if !bytes.Contains(a.b, []byte("Q to quit")) {
		t.Fatal("footer missing during settings navigation")
	}

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)
}

func TestHome2FAQRCodeAndCopy(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword2FA)
	var copied []string
	deps.CopyText = func(s string) error {
		copied = append(copied, s)
		return nil
	}
	if err := os.WriteFile(filepath.Join(deps.StartDir, "a.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Select a file to encrypt", "a.txt")
	pickATxt(tm, true)
	waitFor(t, tm, a, "Secret (password+2fa)")
	tm.Type("correct horse battery staple")
	tm.Send(key(tea.KeyEnter))

	waitFor(t, tm, a, "█", "Scan the QR", "Enter the 6-digit code")
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	waitFor(t, tm, a, "copied 2FA URI to clipboard")
	if len(copied) != 1 || !strings.HasPrefix(copied[0], "otpauth://") {
		t.Fatalf("clipboard got %q, want the otpauth URI", copied)
	}

	tm.Type("123456")
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, ".pbx")

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)

	if _, err := os.Stat(filepath.Join(deps.StartDir, "a.txt.pbx")); err != nil {
		t.Fatalf("no .pbx output: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(deps.StartDir, "a.txt.pbx"))
	if err != nil || !strings.HasPrefix(string(b), "PBX1 ") {
		t.Fatalf("no single-file PBX1 output: %v", err)
	}
}

func TestPINSecretRulesShort(t *testing.T) {
	rules := auth.SecretRules(keystore.ModePIN)
	if len(rules) != 1 || rules[0] != "PIN: 6 to 12 digits, numbers only." {
		t.Fatalf("PIN rules = %#v", rules)
	}
}
