package tui

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
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
	return bytes.Repeat([]byte{0x42}, 20), "otpauth://totp/Pillarbox:pillarbox?secret=FAKE", nil
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
		Store:    keystore.NewStore(filepath.Join(dir, "cfg", "keystore.json")),
		Wrapper:  keystore.NewWrapper(),
		KDF:      auth.NewKDF(),
		TOTP:     &fakeTOTP{},
		DevStore: auth.NewDeviceSecretStore(filepath.Join(dir, "cfg", "device.key")),
		Vault:    vault.New(),
		Version:  "0.1.0-test",
		StartDir: dir,
	}
}

func setupKeystore(t *testing.T, d *Deps, mode keystore.Mode) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ks, err := auth.NewInitializer(d.KDF, d.Wrapper).Initialize(
		mode, id.Recipient().String(),
		[]byte(id.String()), []byte("correct horse battery staple"), nil, nil,
		keystore.Argon2Params{Time: 1, Memory: 1024, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Store.Save(ks); err != nil {
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

func TestOnboardingAllModesKeyboardOnly(t *testing.T) {
	modes := []struct {
		name   string
		index  int
		secret string
		has2FA bool
	}{
		{string(keystore.ModePassword), 0, "correct horse battery staple", false},
		{string(keystore.ModePIN), 1, "123456", false},
		{string(keystore.ModePassword2FA), 2, "correct horse battery staple", true},
		{string(keystore.ModePIN2FA), 3, "123456", true},
	}
	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			deps := testDeps(t)
			tm := teatest.NewTestModel(t, NewOnboarding(deps), teatest.WithInitialTermSize(80, 24))
			a := &acc{}

			tm.Send(key(tea.KeyEnter)) // welcome -> mode
			waitFor(t, tm, a, "Unlock mode")
			for i := 0; i < tc.index; i++ {
				tm.Send(key(tea.KeyDown))
			}
			tm.Send(key(tea.KeyEnter)) // select mode
			waitFor(t, tm, a, "Secret")

			tm.Type(tc.secret)
			tm.Send(key(tea.KeyEnter)) // to confirm field
			tm.Type(tc.secret)
			tm.Send(key(tea.KeyEnter)) // confirm

			if tc.has2FA {
				waitFor(t, tm, a, "2FA")
				tm.Type("123456")
				tm.Send(key(tea.KeyEnter)) // code accepted
				waitFor(t, tm, a, "Require 2FA")
				tm.Send(key(tea.KeyEnter)) // gate-encrypt: default No
			}

			waitFor(t, tm, a, "Recovery key")
			tm.Type("saved")
			tm.Send(key(tea.KeyEnter)) // finalize

			tm.WaitFinished(t)

			ks, err := deps.Store.Load()
			if err != nil {
				t.Fatalf("keystore not written: %v", err)
			}
			if ks.Mode != keystore.Mode(tc.name) {
				t.Fatalf("mode = %q, want %q", ks.Mode, tc.name)
			}
			info, err := os.Stat(deps.Store.Path())
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("keystore mode = %o, want 600", info.Mode().Perm())
			}
		})
	}
}

func TestOnboardingEscBeforeLastScreenLeavesNoKeystore(t *testing.T) {
	deps := testDeps(t)
	tm := teatest.NewTestModel(t, NewOnboarding(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}

	tm.Send(key(tea.KeyEnter)) // welcome -> mode
	waitFor(t, tm, a, "Unlock mode")
	tm.Send(key(tea.KeyDown))
	tm.Send(key(tea.KeyEnter)) // pin
	waitFor(t, tm, a, "Secret")
	tm.Type("123456")
	tm.Send(key(tea.KeyEnter))
	tm.Type("123456")
	tm.Send(key(tea.KeyEnter)) // -> recovery screen
	waitFor(t, tm, a, "Recovery key")

	// Esc walks back screen by screen and finally quits; nothing was written.
	for i := 0; i < 10; i++ {
		tm.Send(key(tea.KeyEsc))
		time.Sleep(50 * time.Millisecond)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(10*time.Second))

	exists, err := deps.Store.Exists()
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("keystore exists after Esc before the last screen completed")
	}
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]|\x1b\\][^\x07]*\x07")

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

func TestViewsFit80x24(t *testing.T) {
	deps := testDeps(t)
	m := NewOnboarding(deps)
	m.width, m.height = 80, 24
	for s := screenWelcome; s <= screenRecovery; s++ {
		m.screen = s
		v := stripANSI(m.View())
		lines := strings.Split(v, "\n")
		if len(lines) > 24 {
			t.Fatalf("onboarding screen %d: %d lines > 24", s, len(lines))
		}
		for _, l := range lines {
			if w := len([]rune(l)); w > 80 {
				t.Fatalf("onboarding screen %d: line width %d > 80: %q", s, w, l)
			}
		}
	}

	setupKeystore(t, deps, keystore.ModePassword)
	h := NewHome(deps)
	h.width, h.height = 80, 24
	for _, s := range []homeScreen{homeMenu, homeStatus, homeHelp, homeResult} {
		h.screen = s
		v := stripANSI(h.View())
		lines := strings.Split(v, "\n")
		if len(lines) > 24 {
			t.Fatalf("home screen %d: %d lines > 24", s, len(lines))
		}
		for _, l := range lines {
			if w := len([]rune(l)); w > 80 {
				t.Fatalf("home screen %d: line width %d > 80: %q", s, w, l)
			}
		}
	}
}

var sgrRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

func TestNoColorHonored(t *testing.T) {
	// CLICOLOR_FORCE would enable color on a pipe; NO_COLOR must win.
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("NO_COLOR", "1")

	deps := testDeps(t)
	tm := teatest.NewTestModel(t, NewOnboarding(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Welcome")
	_ = tm.Quit()

	if sgrRe.Match(a.b) {
		t.Fatal("output contains SGR color sequences despite NO_COLOR")
	}
}

func TestColorUsedWhenAllowed(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("NO_COLOR", "")

	deps := testDeps(t)
	tm := teatest.NewTestModel(t, NewOnboarding(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Welcome")
	_ = tm.Quit()

	if !sgrRe.Match(a.b) {
		t.Fatal("expected SGR color sequences with CLICOLOR_FORCE and no NO_COLOR")
	}
}

func TestHomeMenuAndLockViaPicker(t *testing.T) {
	deps := testDeps(t)
	setupKeystore(t, deps, keystore.ModePassword)
	if err := os.WriteFile(filepath.Join(deps.StartDir, "a.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Encrypt", "Decrypt", "Status", "Settings", "Help")

	tm.Send(key(tea.KeyEnter)) // Encrypt is the first item
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && !bytes.Contains(a.b, []byte("a.txt")) {
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			a.b = append(a.b, b...)
			return bytes.Contains(a.b, []byte("a.txt"))
		}, teatest.WithDuration(500*time.Millisecond))
	}
	if !bytes.Contains(a.b, []byte("a.txt")) {
		t.Fatalf("picker never showed a.txt; acc tail:\n%s", a.b[max(0, len(a.b)-800):])
	}
	tm.Send(key(tea.KeyDown))  // cursor: cfg/ -> a.txt
	tm.Send(key(tea.KeyEnter)) // pick the file
	waitFor(t, tm, a, ".pbx")  // result screen

	tm.Send(key(tea.KeyEsc)) // back to menu
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)

	if _, err := os.Stat(filepath.Join(deps.StartDir, "a.txt.pbx")); err != nil {
		t.Fatalf("lock via picker did not produce a.txt.pbx: %v", err)
	}
}

func TestHomeMenuTabNavigation(t *testing.T) {
	deps := testDeps(t)
	setupKeystore(t, deps, keystore.ModePassword)
	if err := os.WriteFile(filepath.Join(deps.StartDir, "a.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	tm := teatest.NewTestModel(t, NewHome(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}
	waitFor(t, tm, a, "Encrypt", "Decrypt", "Status", "Settings", "Help")

	// Tab moves the selection to Decrypt; Enter opens the secret prompt.
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, "Secret")

	// Shift+Tab moves back to Encrypt; Enter opens the file picker.
	tm.Send(key(tea.KeyEsc))
	tm.Send(tea.KeyMsg{Type: tea.KeyShiftTab})
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, "a.txt")

	tm.Send(key(tea.KeyEsc))
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t)
}

func TestOnboarding2FAQRCodeAndCopy(t *testing.T) {
	deps := testDeps(t)
	var copied []string
	deps.CopyText = func(s string) error {
		copied = append(copied, s)
		return nil
	}

	tm := teatest.NewTestModel(t, NewOnboarding(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}

	tm.Send(key(tea.KeyEnter)) // welcome -> mode
	waitFor(t, tm, a, "Unlock mode")
	tm.Send(key(tea.KeyDown))
	tm.Send(key(tea.KeyDown)) // password+2fa
	tm.Send(key(tea.KeyEnter))
	waitFor(t, tm, a, "Secret (")
	for _, r := range "correct horse battery staple" {
		tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	tm.Send(key(tea.KeyEnter)) // -> confirm
	for _, r := range "correct horse battery staple" {
		tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	tm.Send(key(tea.KeyEnter)) // -> 2FA screen

	// The 2FA screen renders the QR code (block glyphs) and the URI.
	waitFor(t, tm, a, "█", "otpauth://")

	// Ctrl+C on the 2FA screen copies the URI instead of quitting.
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	waitFor(t, tm, a, "copied 2FA URI to clipboard")
	if len(copied) != 1 || !strings.HasPrefix(copied[0], "otpauth://") {
		t.Fatalf("clipboard got %q, want the otpauth URI", copied)
	}

	// Esc back to welcome, then Ctrl+C quits; no keystore is written.
	tm.Send(key(tea.KeyEsc))
	tm.Send(key(tea.KeyEsc))
	tm.Send(key(tea.KeyEsc))
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	tm.WaitFinished(t)
	if ok, _ := deps.Store.Exists(); ok {
		t.Fatal("keystore written despite Esc before the last screen")
	}
}

func TestOnboardingSecretScreenShowsRules(t *testing.T) {
	deps := testDeps(t)
	tm := teatest.NewTestModel(t, NewOnboarding(deps), teatest.WithInitialTermSize(80, 24))
	a := &acc{}

	tm.Send(key(tea.KeyEnter)) // welcome -> mode
	waitFor(t, tm, a, "Unlock mode")
	tm.Send(key(tea.KeyEnter)) // password mode -> secret screen

	// The rules and their reasons are visible before any typing.
	waitFor(t, tm, a, "at least 12 characters", "You need", "Secret:")

	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	tm.WaitFinished(t)
}
