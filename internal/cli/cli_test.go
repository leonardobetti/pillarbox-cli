package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/leonardobetti/pillarbox-cli/internal/auth"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
	"github.com/leonardobetti/pillarbox-cli/internal/vault"
)

const testSecret = "correct horse battery staple"

// env is a fully wired CLI with the real core services rooted in a temp dir.
type env struct {
	dir      string
	deps     *Deps
	src, pbx string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	return &env{
		dir: dir,
		deps: &Deps{
			Settings: keystore.NewSettingsStore(filepath.Join(dir, "cfg", "settings.json")),
			Wrapper:  keystore.NewWrapper(),
			KDF:      auth.NewKDF(),
			TOTP:     auth.NewTOTP(),
			DevStore: auth.NewDeviceSecretStore(filepath.Join(dir, "cfg", "device.key")),
			Vault:    vault.New(),
			Stdin:    strings.NewReader(""),
			Stdout:   new(bytes.Buffer),
			Stderr:   new(bytes.Buffer),
		},
	}
}

func (e *env) run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	e.deps.Stdin = strings.NewReader(stdin)
	e.deps.Stdout = new(bytes.Buffer)
	e.deps.Stderr = new(bytes.Buffer)
	code := Run(args, e.deps)
	out := e.deps.Stdout.(*bytes.Buffer).String()
	errOut := e.deps.Stderr.(*bytes.Buffer).String()
	return code, out, errOut
}

// fakeTOTP is deterministic so 2FA flows are testable without waiting on the
// 30-second step.
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

// seedSettings writes the settings file with the given key type.
func seedSettings(t *testing.T, e *env, mode keystore.Mode) {
	t.Helper()
	if err := e.deps.Settings.Save(&keystore.Settings{KeyType: mode}); err != nil {
		t.Fatalf("Save settings: %v", err)
	}
}

func initPassword(t *testing.T, e *env) {
	t.Helper()
	seedSettings(t, e, keystore.ModePassword)
}

// setupLocked configures the key type and locks a file with its own key,
// leaving e.src and e.pbx set.
func (e *env) setupLocked(t *testing.T, mode, secret string) {
	t.Helper()
	m := keystore.Mode(mode)
	seedSettings(t, e, m)
	if m.Has2FA() {
		e.deps.TOTP = &fakeTOTP{}
	}
	e.src = makeFile(t, e, "a.txt", "hello pillarbox")
	args := []string{"lock", e.src, "--no-tui", "--secret-stdin"}
	if m.Has2FA() {
		args = append(args, "--totp", "123456")
	}
	code, out, errOut := e.run(t, secret+"\n", args...)
	if code != ExitOK {
		t.Fatalf("lock: exit %d, stderr %q", code, errOut)
	}
	e.pbx = strings.TrimSpace(strings.Split(out, "\n")[0])
}

func makeFile(t *testing.T, e *env, name, content string) string {
	t.Helper()
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCommandsTable(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, e *env)
		args     func(t *testing.T, e *env) []string
		stdin    string
		wantExit int
		wantOut  string
		wantErr  string
		check    func(t *testing.T, e *env, out, errOut string)
	}{
		{
			name:     "version",
			args:     func(t *testing.T, e *env) []string { return []string{"version"} },
			wantExit: ExitOK,
			wantOut:  "pillarbox version",
		},
		{
			name:     "status without settings shows not set",
			args:     func(t *testing.T, e *env) []string { return []string{"status"} },
			wantExit: ExitOK,
			wantOut:  "not set",
		},
		{
			name:     "init is no longer a command",
			args:     func(t *testing.T, e *env) []string { return []string{"init"} },
			wantExit: ExitUsage,
			wantErr:  "unknown command",
		},
		{
			name:     "lock without key type exits 5",
			args:     func(t *testing.T, e *env) []string { return []string{"lock", "x", "--no-tui"} },
			wantExit: ExitKeystore,
			wantErr:  "no key type configured",
		},
		{
			name:     "lock missing path exits 2",
			setup:    func(t *testing.T, e *env) { initPassword(t, e) },
			args:     func(t *testing.T, e *env) []string { return []string{"lock"} },
			wantExit: ExitUsage,
		},
		{
			name: "lock file",
			setup: func(t *testing.T, e *env) {
				initPassword(t, e)
				e.src = makeFile(t, e, "a.txt", "hello")
			},
			args:     func(t *testing.T, e *env) []string { return []string{"lock", e.src, "--no-tui", "--secret-stdin"} },
			stdin:    testSecret + "\n",
			wantExit: ExitOK,
			wantOut:  ".pbx",
			check: func(t *testing.T, e *env, out, errOut string) {
				dst := strings.TrimSpace(strings.Split(out, "\n")[0])
				b, err := os.ReadFile(dst)
				if err != nil {
					t.Fatalf("no output file: %v", err)
				}
				if !strings.HasPrefix(string(b), "PBX1 ") {
					t.Fatal("output is not a single-file PBX1 .pbx")
				}
				if _, err := os.Stat(dst + ".key"); !os.IsNotExist(err) {
					t.Fatal("sidecar .key file should not exist anymore")
				}
			},
		},
		{
			name: "lock a folder exits 2",
			setup: func(t *testing.T, e *env) {
				initPassword(t, e)
				if err := os.Mkdir(filepath.Join(e.dir, "adir"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"lock", filepath.Join(e.dir, "adir"), "--no-tui", "--secret-stdin"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitUsage,
			wantErr:  "folders are not supported",
		},
		{
			name: "lock quiet prints nothing",
			setup: func(t *testing.T, e *env) {
				initPassword(t, e)
				e.src = makeFile(t, e, "a.txt", "hello")
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"lock", e.src, "--no-tui", "--quiet", "--secret-stdin"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitOK,
			check: func(t *testing.T, e *env, out, errOut string) {
				if out != "" {
					t.Fatalf("quiet lock printed %q", out)
				}
			},
		},
		{
			name: "unlock round trip",
			setup: func(t *testing.T, e *env) {
				e.setupLocked(t, "password", testSecret)
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"unlock", e.pbx, "-o", filepath.Join(e.dir, "out.txt"), "--no-tui", "--secret-stdin"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitOK,
			check: func(t *testing.T, e *env, out, errOut string) {
				b, err := os.ReadFile(filepath.Join(e.dir, "out.txt"))
				if err != nil || string(b) != "hello pillarbox" {
					t.Fatalf("round trip content = %q, %v", b, err)
				}
			},
		},
		{
			name: "unlock wrong secret exits 3",
			setup: func(t *testing.T, e *env) {
				e.setupLocked(t, "password", testSecret)
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"unlock", e.pbx, "-o", filepath.Join(e.dir, "out.txt"), "--no-tui", "--secret-stdin"}
			},
			stdin:    "wrong secret\n",
			wantExit: ExitAuth,
			wantErr:  "authentication failed",
		},
		{
			name: "unlock tampered file exits 4",
			setup: func(t *testing.T, e *env) {
				e.setupLocked(t, "password", testSecret)
				b, err := os.ReadFile(e.pbx)
				if err != nil {
					t.Fatal(err)
				}
				b[len(b)-10] ^= 0x01 // flip a byte in the age payload, past the PBX1 header
				if err := os.WriteFile(e.pbx, b, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"unlock", e.pbx, "-o", filepath.Join(e.dir, "out.txt"), "--no-tui", "--secret-stdin"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitIntegrity,
			wantErr:  "integrity",
		},
		{
			name: "unlock to missing output dir exits 1 not 4",
			setup: func(t *testing.T, e *env) {
				e.setupLocked(t, "password", testSecret)
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"unlock", e.pbx, "-o", filepath.Join(e.dir, "no-such-dir", "out.txt"), "--no-tui", "--secret-stdin"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitOther,
			check: func(t *testing.T, e *env, out, errOut string) {
				if strings.Contains(errOut, "integrity") {
					t.Fatalf("infrastructure error reported as integrity: %q", errOut)
				}
			},
		},
		{
			name: "unlock without secret input exits 2",
			setup: func(t *testing.T, e *env) {
				e.setupLocked(t, "password", testSecret)
			},
			args:     func(t *testing.T, e *env) []string { return []string{"unlock", e.pbx, "--no-tui"} },
			wantExit: ExitUsage,
			wantErr:  "--secret-stdin",
		},
		{
			name: "unlock without embedded key exits 5",
			setup: func(t *testing.T, e *env) {
				initPassword(t, e)
				makeFile(t, e, "orphan.pbx", "not a pillarbox file")
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"unlock", filepath.Join(e.dir, "orphan.pbx"), "--no-tui", "--secret-stdin"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitKeystore,
			wantErr:  "no key for this file",
		},
		{
			name:     "status after settings",
			setup:    func(t *testing.T, e *env) { initPassword(t, e) },
			args:     func(t *testing.T, e *env) []string { return []string{"status"} },
			wantExit: ExitOK,
			wantOut:  "key type: password",
		},
		{
			name:  "export-key prints recovery key",
			setup: func(t *testing.T, e *env) { e.setupLocked(t, "password", testSecret) },
			args: func(t *testing.T, e *env) []string {
				return []string{"export-key", e.pbx, "--no-tui", "--secret-stdin"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitOK,
			wantOut:  "AGE-SECRET-KEY-1",
		},
		{
			name:  "export-key wrong secret exits 3",
			setup: func(t *testing.T, e *env) { e.setupLocked(t, "password", testSecret) },
			args: func(t *testing.T, e *env) []string {
				return []string{"export-key", e.pbx, "--no-tui", "--secret-stdin"}
			},
			stdin:    "nope\n",
			wantExit: ExitAuth,
		},
		{
			name:     "config set key-type",
			setup:    func(t *testing.T, e *env) { initPassword(t, e) },
			args:     func(t *testing.T, e *env) []string { return []string{"config", "set", "key-type", "pin+2fa"} },
			wantExit: ExitOK,
			wantOut:  "key-type set",
		},
		{
			name:     "config set gate-encrypt true",
			setup:    func(t *testing.T, e *env) { initPassword(t, e) },
			args:     func(t *testing.T, e *env) []string { return []string{"config", "set", "gate-encrypt", "true"} },
			wantExit: ExitOK,
			wantOut:  "gate-encrypt set",
		},
		{
			name:     "config set bad value exits 2",
			setup:    func(t *testing.T, e *env) { initPassword(t, e) },
			args:     func(t *testing.T, e *env) []string { return []string{"config", "set", "gate-encrypt", "maybe"} },
			wantExit: ExitUsage,
		},
		{
			name:     "config unknown key exits 2",
			setup:    func(t *testing.T, e *env) { initPassword(t, e) },
			args:     func(t *testing.T, e *env) []string { return []string{"config", "set", "bogus", "true"} },
			wantExit: ExitUsage,
		},
		{
			name: "lock with gate-encrypt and no secret exits 2",
			setup: func(t *testing.T, e *env) {
				initPassword(t, e)
				if code, _, errOut := e.run(t, "", "config", "set", "gate-encrypt", "true"); code != ExitOK {
					t.Fatalf("config set: exit %d, %q", code, errOut)
				}
				e.src = makeFile(t, e, "a.txt", "hello")
			},
			args:     func(t *testing.T, e *env) []string { return []string{"lock", e.src, "--no-tui"} },
			wantExit: ExitUsage,
		},
		{
			name: "lock with gate-encrypt and secret-stdin",
			setup: func(t *testing.T, e *env) {
				initPassword(t, e)
				if code, _, errOut := e.run(t, "", "config", "set", "gate-encrypt", "true"); code != ExitOK {
					t.Fatalf("config set: exit %d, %q", code, errOut)
				}
				e.src = makeFile(t, e, "a.txt", "hello")
			},
			args:     func(t *testing.T, e *env) []string { return []string{"lock", e.src, "--no-tui", "--secret-stdin"} },
			stdin:    testSecret + "\n",
			wantExit: ExitOK,
		},
		{
			name: "pin mode round trip",
			setup: func(t *testing.T, e *env) {
				e.setupLocked(t, "pin", "123456")
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"unlock", e.pbx, "-o", filepath.Join(e.dir, "out.txt"), "--no-tui", "--secret-stdin"}
			},
			stdin:    "123456\n",
			wantExit: ExitOK,
			check: func(t *testing.T, e *env, out, errOut string) {
				b, err := os.ReadFile(filepath.Join(e.dir, "out.txt"))
				if err != nil || string(b) != "hello pillarbox" {
					t.Fatalf("pin round trip content = %q, %v", b, err)
				}
			},
		},
		{
			name: "2fa unlock ok",
			setup: func(t *testing.T, e *env) {
				e.setupLocked(t, "password+2fa", testSecret)
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"unlock", e.pbx, "-o", filepath.Join(e.dir, "out.txt"), "--no-tui", "--secret-stdin", "--totp", "123456"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitOK,
		},
		{
			name: "2fa wrong totp exits 3",
			setup: func(t *testing.T, e *env) {
				e.setupLocked(t, "password+2fa", testSecret)
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"unlock", e.pbx, "-o", filepath.Join(e.dir, "out.txt"), "--no-tui", "--secret-stdin", "--totp", "000000"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitAuth,
		},
		{
			name: "2fa reused totp exits 3",
			setup: func(t *testing.T, e *env) {
				e.setupLocked(t, "password+2fa", testSecret)
				code, _, errOut := e.run(t, testSecret+"\n", "unlock", e.pbx, "-o", filepath.Join(e.dir, "out1.txt"), "--no-tui", "--secret-stdin", "--totp", "123456")
				if code != ExitOK {
					t.Fatalf("first unlock: exit %d, %q", code, errOut)
				}
			},
			args: func(t *testing.T, e *env) []string {
				return []string{"unlock", e.pbx, "-o", filepath.Join(e.dir, "out2.txt"), "--no-tui", "--secret-stdin", "--totp", "123456"}
			},
			stdin:    testSecret + "\n",
			wantExit: ExitAuth,
		},
		{
			name:     "unknown command exits 2",
			args:     func(t *testing.T, e *env) []string { return []string{"frobnicate"} },
			wantExit: ExitUsage,
		},
		{
			name:     "unknown flag exits 2",
			args:     func(t *testing.T, e *env) []string { return []string{"version", "--bogus"} },
			wantExit: ExitUsage,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.setup != nil {
				tc.setup(t, e)
			}
			code, out, errOut := e.run(t, tc.stdin, tc.args(t, e)...)
			if code != tc.wantExit {
				t.Fatalf("exit = %d, want %d (stderr %q)", code, tc.wantExit, errOut)
			}
			if tc.wantOut != "" && !strings.Contains(out, tc.wantOut) {
				t.Fatalf("stdout %q does not contain %q", out, tc.wantOut)
			}
			if tc.wantErr != "" && !strings.Contains(errOut, tc.wantErr) {
				t.Fatalf("stderr %q does not contain %q", errOut, tc.wantErr)
			}
			if tc.check != nil {
				tc.check(t, e, out, errOut)
			}
		})
	}
}

func TestHelpListsAllCommands(t *testing.T) {
	e := newEnv(t)
	code, out, _ := e.run(t, "", "--help")
	if code != ExitOK {
		t.Fatalf("--help exit = %d, want 0", code)
	}
	for _, name := range []string{"lock", "unlock", "status", "export-key", "config", "version"} {
		if !strings.Contains(out, name) {
			t.Errorf("--help output is missing command %q", name)
		}
	}
}

// TestNoSecretInArgs scans the command tree: no flag or argument may be named
// like a secret carrier other than --secret-stdin (a bool) and --totp (PRD 9).
func TestNoSecretAsArgument(t *testing.T) {
	e := newEnv(t)
	cmd := newRoot(e.deps)
	var bad []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if strings.Contains(f.Name, "secret") && f.Name != "secret-stdin" {
			bad = append(bad, f.Name)
		}
	})
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if strings.Contains(f.Name, "secret") && f.Name != "secret-stdin" {
			bad = append(bad, f.Name)
		}
	})
	if len(bad) > 0 {
		t.Fatalf("secret-taking flags found: %v", bad)
	}
}
