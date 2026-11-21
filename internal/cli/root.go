package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"

	"github.com/leonardobetti/pillarbox-cli/internal/auth"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
	"github.com/leonardobetti/pillarbox-cli/internal/tui"
	"github.com/leonardobetti/pillarbox-cli/internal/vault"
)

// Deps wires the core services into the CLI. Production uses DefaultDeps;
// tests inject real implementations rooted in temp dirs or fakes.
type Deps struct {
	Settings keystore.SettingsStore
	Wrapper  keystore.Wrapper
	KDF      auth.KDF
	TOTP     auth.TOTP
	DevStore auth.DeviceSecretStore
	Vault    vault.Vault
	Prompter auth.SecretPrompter
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer

	opts options
}

// options holds the global flags, PRD section 9.
type options struct {
	noTUI       bool
	secretStdin bool
	totp        string
	quiet       bool
}

// exitError carries a process exit code and a one-line message, PRD 9.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// Execute runs the CLI against the real core services and returns the exit
// code.
func Execute() int {
	deps, err := DefaultDeps()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pillarbox: cannot initialize the config directory")
		return ExitOther
	}
	return Run(os.Args[1:], deps)
}

// DefaultDeps builds Deps from the real implementations and process stdio.
func DefaultDeps() (*Deps, error) {
	settings, err := keystore.DefaultSettingsStore()
	if err != nil {
		return nil, err
	}
	devPath, err := auth.DefaultDeviceSecretPath()
	if err != nil {
		return nil, err
	}
	return &Deps{
		Settings: settings,
		Wrapper:  keystore.NewWrapper(),
		KDF:      auth.NewKDF(),
		TOTP:     auth.NewTOTP(),
		DevStore: auth.NewDeviceSecretStore(devPath),
		Vault:    vault.New(),
		Prompter: termPrompter{},
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
	}, nil
}

// Run executes one CLI invocation and returns the process exit code, PRD 9.
// A fresh command tree is built per call so flag state never leaks between
// invocations.
func Run(args []string, d *Deps) int {
	if d.Stdout == nil {
		d.Stdout = os.Stdout
	}
	if d.Stderr == nil {
		d.Stderr = os.Stderr
	}
	if d.Stdin == nil {
		d.Stdin = os.Stdin
	}
	cmd := newRoot(d)
	cmd.SetArgs(args)
	cmd.SetOut(d.Stdout)
	cmd.SetErr(d.Stderr)

	err := cmd.Execute()
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		d.warn(ee.msg)
		return ee.code
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "unknown command") ||
		strings.HasPrefix(msg, "unknown flag") ||
		strings.HasPrefix(msg, "unknown shorthand flag") ||
		strings.HasPrefix(msg, "invalid argument") {
		d.warn(msg)
		return ExitUsage
	}
	d.warn(msg)
	return ExitOther
}

func newRoot(d *Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "pillarbox",
		Short:         "Pillarbox encrypts and decrypts files from the terminal",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          exactArgs(0, "unknown command; see pillarbox --help"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runRoot(cmd)
		},
	}
	cmd.PersistentFlags().BoolVar(&d.opts.noTUI, "no-tui", false, "disable all interactive screens")
	cmd.PersistentFlags().BoolVar(&d.opts.secretStdin, "secret-stdin", false, "read the secret from stdin instead of prompting")
	cmd.PersistentFlags().StringVar(&d.opts.totp, "totp", "", "TOTP code for 2FA modes")
	cmd.PersistentFlags().BoolVar(&d.opts.quiet, "quiet", false, "suppress informational output")
	cmd.AddCommand(
		newLockCmd(d),
		newUnlockCmd(d),
		newStatusCmd(d),
		newExportKeyCmd(d),
		newConfigCmd(d),
		newVersionCmd(),
	)
	return cmd
}

// runRoot handles bare pillarbox, PRD 8.1 and 8.2. On a terminal without
// --no-tui it runs onboarding when the keystore is missing and the home menu
// otherwise; non-interactive it exits 5 or prints help.
func (d *Deps) runRoot(cmd *cobra.Command) error {
	exists, err := d.Settings.Exists()
	if err == nil && !exists && d.interactive() {
		if _, terr := tui.RunOnboarding(d.tuiDeps()); terr == nil {
			exists, _ = d.Settings.Exists()
		}
	}
	if err == nil && !exists {
		return &exitError{ExitKeystore, "no settings; run pillarbox to set up"}
	}
	if d.interactive() {
		if _, terr := tui.RunHome(d.tuiDeps()); terr != nil {
			return &exitError{ExitOther, "the interactive UI exited with an error"}
		}
		return nil
	}
	return cmd.Help()
}

// interactive reports whether a TUI may run: a terminal on stdin and stdout
// and no --no-tui.
func (d *Deps) interactive() bool {
	return !d.opts.noTUI && isTerminal(d.Stdin) && isTerminalWriter(d.Stdout)
}

func (d *Deps) tuiDeps() *tui.Deps {
	return &tui.Deps{
		Settings: d.Settings,
		Wrapper:  d.Wrapper,
		KDF:      d.KDF,
		TOTP:     d.TOTP,
		DevStore: d.DevStore,
		Vault:    d.Vault,
		Version:  Version,
		StartDir: ".",
		CopyText: clipboard.WriteAll,
	}
}

// printf and println write informational output; a failed write to stdout is
// deliberately ignored so the command's exit code stays the signal.
func (d *Deps) printf(format string, a ...any) {
	_, _ = fmt.Fprintf(d.Stdout, format, a...)
}

func (d *Deps) println(a ...any) {
	_, _ = fmt.Fprintln(d.Stdout, a...)
}

// warn writes a one-line message to stderr; a failed write is ignored.
func (d *Deps) warn(a ...any) {
	_, _ = fmt.Fprintln(d.Stderr, a...)
}

// exactArgs returns a cobra arg validator that reports usage errors with exit
// code 2.
func exactArgs(n int, usage string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return &exitError{ExitUsage, usage}
		}
		return nil
	}
}

// loadSettings loads the settings file. A missing file is empty settings, an
// invalid one is exit 5. On a terminal, missing settings start onboarding.
func (d *Deps) loadSettings() (*keystore.Settings, error) {
	st, err := d.Settings.Load()
	if errors.Is(err, keystore.ErrInvalid) && d.interactive() {
		if _, terr := tui.RunOnboarding(d.tuiDeps()); terr == nil {
			st, err = d.Settings.Load()
		}
	}
	if errors.Is(err, keystore.ErrInvalid) {
		return nil, &exitError{ExitKeystore, "settings invalid; run pillarbox to set up"}
	}
	if err != nil {
		return nil, &exitError{ExitOther, "cannot read settings"}
	}
	return st, nil
}

// keyType resolves the key type for a new file: the configured one from
// Settings, or exit 5 when unset. The interactive chooser lives in the TUI.
func (d *Deps) keyType() (keystore.Mode, error) {
	st, err := d.loadSettings()
	if err != nil {
		return "", err
	}
	if !st.KeyType.Valid() {
		return "", &exitError{ExitKeystore, "no key type configured; run pillarbox and set it in Settings"}
	}
	return st.KeyType, nil
}

// buildFileKey creates the per-file key for a new .pbx: secret from the
// user, device secret for PIN modes, TOTP seed for 2FA modes, and a fresh age
// identity wrapped under the KEK. The key is embedded in the .pbx header at
// lock time. It returns the keystore and the raw recovery key.
func (d *Deps) buildFileKey(mode keystore.Mode) (*keystore.Keystore, string, error) {
	secret, err := d.readSecret(false)
	if err != nil {
		return nil, "", err
	}
	if err := auth.ValidateSecret(mode, secret); err != nil {
		return nil, "", &exitError{ExitUsage, "invalid secret: " + err.Error()}
	}
	var devSecret []byte
	if mode.HasDeviceSecret() {
		devSecret, _, err = d.DevStore.LoadOrCreate()
		if err != nil {
			return nil, "", &exitError{ExitOther, "cannot write device secret"}
		}
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, "", &exitError{ExitOther, "cannot generate identity"}
	}
	var seed []byte
	if mode.Has2FA() {
		var uri string
		// PILLARBOX_E2E_TOTP_SEED is a test hook used only by scripts/e2e.sh;
		// it is unset in production and still requires a valid code.
		if s := os.Getenv("PILLARBOX_E2E_TOTP_SEED"); s != "" {
			seed, uri, err = auth.GenerateSeedFromBase32(s)
		} else {
			seed, uri, err = d.TOTP.GenerateSeed()
		}
		if err != nil {
			return nil, "", &exitError{ExitOther, "cannot generate TOTP seed"}
		}
		if d.interactive() {
			d.println("2FA URI: " + uri)
		}
		code, err := d.readTOTP()
		if err != nil {
			return nil, "", err
		}
		ok, _, verr := d.TOTP.Verify(seed, code, -1)
		if verr != nil || !ok {
			return nil, "", &exitError{ExitAuth, "authentication failed; check the secret and the 2FA code"}
		}
	}
	ks, err := auth.NewInitializer(d.KDF, d.Wrapper).Initialize(
		mode, identity.Recipient().String(), []byte(identity.String()), secret, devSecret, seed, keystore.DefaultArgon2Params)
	if err != nil {
		return nil, "", &exitError{ExitOther, "cannot build file key"}
	}
	return ks, identity.String(), nil
}

// loadFileKey loads the per-file key embedded in the .pbx header (or the
// v0.2.0 sidecar). Missing or invalid key is exit 5.
func (d *Deps) loadFileKey(src string) (*keystore.Keystore, error) {
	ks, err := d.Vault.ReadKey(src)
	if errors.Is(err, keystore.ErrNotFound) || errors.Is(err, keystore.ErrInvalid) {
		return nil, &exitError{ExitKeystore, "no key for this file or key invalid"}
	}
	if err != nil {
		return nil, &exitError{ExitOther, "cannot read file key"}
	}
	return ks, nil
}

// authenticate runs the unlock flow and maps failures to exit codes: no input
// is 2, a wrong secret or code is 3.
func (d *Deps) authenticate(ks *keystore.Keystore) (identity []byte, newStep int64, err error) {
	// When prompting on a terminal, state the secret rules before the prompt
	// so the user is not surprised by a rejection. Scripts using
	// --secret-stdin get no extra output.
	if !d.opts.secretStdin && d.Prompter != nil && isTerminal(d.Stdin) {
		for _, rule := range auth.SecretRules(ks.Mode) {
			_, _ = fmt.Fprintln(d.Stderr, rule)
		}
	}
	secret, err := d.readSecret(false)
	if err != nil {
		return nil, 0, err
	}
	code := ""
	if ks.Mode.Has2FA() {
		code, err = d.readTOTP()
		if err != nil {
			return nil, 0, err
		}
	}
	id, step, aerr := auth.NewAuthenticator(d.KDF, d.Wrapper, d.DevStore, d.TOTP).Authenticate(ks, secret, code)
	if errors.Is(aerr, auth.ErrAuth) {
		return nil, 0, &exitError{ExitAuth, "authentication failed; check the secret and the 2FA code"}
	}
	if aerr != nil {
		return nil, 0, &exitError{ExitOther, "authentication error"}
	}
	return id, step, nil
}

// mapVaultErr maps vault failures to exit codes, PRD 9.
func mapVaultErr(err error) error {
	switch {
	case errors.Is(err, vault.ErrIntegrity):
		return &exitError{ExitIntegrity, "integrity failure: the file is corrupted, tampered with, or for another key"}
	case errors.Is(err, vault.ErrExists):
		return &exitError{ExitUsage, err.Error()}
	case errors.Is(err, vault.ErrUnsupported):
		return &exitError{ExitUsage, "folders are not supported; encrypt files one by one"}
	default:
		return &exitError{ExitOther, err.Error()}
	}
}
