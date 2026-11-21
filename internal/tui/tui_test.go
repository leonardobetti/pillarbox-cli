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

func TestOnboardingAllKeyTypes(t *testing.T) {
	modes := []keystore.Mode{
		keystore.ModePassword, keystore.ModePIN, keystore.ModePassword2FA, keystore.ModePIN2FA,
	}
	for i, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			deps := testDeps(t)
			tm := teatest.NewTestModel(t, NewOnboarding(deps), teatest.WithInitialTermSize(80, 24))
			a := &acc{}

			tm.Send(key(tea.KeyEnter)) // welcome -> key type
			waitFor(t, tm, a, "Key type for new files")
			for j := 0; j < i; j++ {
				tm.Send(key(tea.KeyDown))
			}
			tm.Send(key(tea.KeyEnter)) // select key type -> gate
			waitFor(t, tm, a, "gate-encrypt")
			tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")}) // apply

			tm.WaitFinished(t)

			st, err := deps.Settings.Load()
			if err != nil {
				t.Fatalf("settings not written: %v", err)
			}
			if st.KeyType != mode {
				t.Fatalf("key type = %q, want %q", st.KeyType, mode)
			}
			info, err := os.Stat(deps.Settings.Path())
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("settings mode = %o, want 600", info.Mode().Perm())
			}
		})
	}
}

func TestOnboardingEscLeavesNoSettings(t *testing.T) {
	deps := testDeps(t)
	tm := teatest.NewTestModel(t, NewOnboarding(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}

	tm.Send(key(tea.KeyEnter)) // welcome -> key type
	waitFor(t, tm, a, "Key type for new files")
	tm.Send(key(tea.KeyEsc)) // back to welcome
	tm.Send(key(tea.KeyEsc)) // quit
	tm.WaitFinished(t)

	if ok, _ := deps.Settings.Exists(); ok {
		t.Fatal("settings written despite Esc before apply")
	}
}

func TestHomeMenuTabNavigation(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)
	if err := os.WriteFile(filepath.Join(deps.StartDir, "a.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Encrypt", "Decrypt", "Settings")

	tm.Send(tea.KeyMsg{Type: tea.KeyTab}) // -> Decrypt
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, "Decrypt — select a .pbx file")

	tm.Send(key(tea.KeyEsc))
	tm.Send(tea.KeyMsg{Type: tea.KeyShiftTab}) // -> Encrypt
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, "Encrypt — select a file")

	tm.Send(key(tea.KeyEsc))
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
	waitFor(t, tm, a, "Encrypt")

	tm.Send(key(tea.KeyEnter)) // Encrypt -> picker
	waitFor(t, tm, a, "a.txt")
	tm.Send(key(tea.KeyDown))  // cursor: cfg/ -> a.txt
	tm.Send(key(tea.KeyEnter)) // pick the file -> secret screen
	waitFor(t, tm, a, "Secret (password)", "at least 12 characters")
	tm.Type("correct horse battery staple")
	tm.Send(key(tea.KeyEnter)) // -> encrypt with a fresh per-file key
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
	waitFor(t, tm, a, "Encrypt")

	tm.Send(key(tea.KeyEnter)) // Encrypt -> picker
	waitFor(t, tm, a, "a.txt")
	tm.Send(key(tea.KeyDown))
	tm.Send(key(tea.KeyEnter)) // pick file -> key type chooser
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
}

func TestHomeSettingsStableNavigation(t *testing.T) {
	deps := testDeps(t)
	setupSettings(t, deps, keystore.ModePassword)

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Settings")
	for i := 0; i < 3; i++ {
		tm.Send(key(tea.KeyDown))
	}
	tm.Send(key(tea.KeyEnter)) // open Settings
	waitFor(t, tm, a, "Key type:", "Gate encrypt:", "a apply")

	// Tab/backspace move down, arrows flip the option: several presses in a
	// row must stay stable, one action per keypress, footer intact.
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})       // cursor -> gate-encrypt
	tm.Send(tea.KeyMsg{Type: tea.KeyBackspace}) // wrap back to key type
	tm.Send(key(tea.KeyDown))                   // cursor -> gate-encrypt
	tm.Send(key(tea.KeyLeft))                   // toggle gate to yes
	waitFor(t, tm, a, "Gate encrypt: yes")
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")}) // apply

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := deps.Settings.Load(); err == nil && st.GateEncrypt {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, err := deps.Settings.Load()
	if err != nil || !st.GateEncrypt {
		t.Fatalf("gate-encrypt not persisted: %v, %+v", err, st)
	}
	if !bytes.Contains(a.b, []byte("ctrl+c abort")) {
		t.Fatal("footer corrupted during settings navigation")
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
	waitFor(t, tm, a, "Encrypt")

	tm.Send(key(tea.KeyEnter)) // Encrypt -> picker
	waitFor(t, tm, a, "a.txt")
	tm.Send(key(tea.KeyDown))
	tm.Send(key(tea.KeyEnter)) // pick file -> secret screen
	waitFor(t, tm, a, "Secret (password+2fa)")
	tm.Type("correct horse battery staple")
	tm.Send(key(tea.KeyEnter)) // -> 2FA QR screen

	waitFor(t, tm, a, "█", "otpauth://")
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	waitFor(t, tm, a, "copied 2FA URI to clipboard")
	if len(copied) != 1 || !strings.HasPrefix(copied[0], "otpauth://") {
		t.Fatalf("clipboard got %q, want the otpauth URI", copied)
	}

	tm.Type("123456")
	tm.Send(key(tea.KeyEnter)) // code accepted -> encrypt
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
