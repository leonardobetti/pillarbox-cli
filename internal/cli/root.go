package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

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
	Store    keystore.Store
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
	store, err := keystore.DefaultStore()
	if err != nil {
		return nil, err
	}
	devPath, err := auth.DefaultDeviceSecretPath()
	if err != nil {
		return nil, err
	}
	return &Deps{
		Store:    store,
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
	exists, err := d.Store.Exists()
	if err == nil && !exists && d.interactive() {
		if _, terr := tui.RunOnboarding(d.tuiDeps()); terr == nil {
			exists, _ = d.Store.Exists()
		}
	}
	if err == nil && !exists {
		return &exitError{ExitKeystore, "no keystore; run pillarbox to set up"}
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
		Store:    d.Store,
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

// loadKeystore loads the keystore and maps missing or invalid to exit 5, PRD
// 8.1 and 9. On a terminal it starts onboarding first when the keystore is
// missing, PRD 8.1.
func (d *Deps) loadKeystore() (*keystore.Keystore, error) {
	ks, err := d.Store.Load()
	if (errors.Is(err, keystore.ErrNotFound) || errors.Is(err, keystore.ErrInvalid)) && d.interactive() {
		if _, terr := tui.RunOnboarding(d.tuiDeps()); terr == nil {
			ks, err = d.Store.Load()
		}
	}
	if errors.Is(err, keystore.ErrNotFound) || errors.Is(err, keystore.ErrInvalid) {
		return nil, &exitError{ExitKeystore, "keystore missing or invalid; run pillarbox to set up"}
	}
	if err != nil {
		return nil, &exitError{ExitOther, "cannot read keystore"}
	}
	return ks, nil
}

// authenticate runs the unlock flow and maps failures to exit codes: no input
// is 2, a wrong secret or code is 3.
func (d *Deps) authenticate(ks *keystore.Keystore) (identity []byte, newStep int64, err error) {
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
	default:
		return &exitError{ExitOther, err.Error()}
	}
}
