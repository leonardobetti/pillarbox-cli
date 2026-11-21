package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// termPrompter reads secrets without echo, PRD section 5 (golang.org/x/term).
// Prompts go to stderr so stdout stays clean for piping. Errors never contain
// the secret itself.
type termPrompter struct{}

func (termPrompter) ReadSecret(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (p termPrompter) ReadSecretTwice(prompt string) ([]byte, error) {
	first, err := p.ReadSecret(prompt)
	if err != nil {
		return nil, err
	}
	second, err := p.ReadSecret("Confirm secret: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, errors.New("secrets do not match")
	}
	return first, nil
}

func (termPrompter) ReadTOTP(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readSecret resolves the secret input. --secret-stdin reads it from stdin;
// otherwise a no-echo terminal prompt is used. With no terminal, no flag and
// no stdin it fails with exit code 2, PRD 8.3. The secret never appears in
// argv, logs or errors.
func (d *Deps) readSecret(twice bool) ([]byte, error) {
	if d.opts.secretStdin {
		data, err := io.ReadAll(d.Stdin)
		if err != nil {
			return nil, &exitError{ExitOther, "cannot read secret from stdin"}
		}
		s := bytes.TrimRight(data, "\r\n")
		if len(s) == 0 {
			return nil, &exitError{ExitUsage, "empty secret on stdin"}
		}
		return s, nil
	}
	if d.opts.noTUI || d.Prompter == nil || !isTerminal(d.Stdin) {
		return nil, &exitError{ExitUsage, "no secret input; use --secret-stdin or run in a terminal"}
	}
	if twice {
		return d.Prompter.ReadSecretTwice("Secret: ")
	}
	return d.Prompter.ReadSecret("Secret: ")
}

// readTOTP resolves the TOTP code: --totp first (PRD 9), else a prompt.
func (d *Deps) readTOTP() (string, error) {
	if d.opts.totp != "" {
		return d.opts.totp, nil
	}
	if d.opts.noTUI || d.Prompter == nil || !isTerminal(d.Stdin) {
		return "", &exitError{ExitUsage, "no TOTP input; pass --totp CODE or run in a terminal"}
	}
	return d.Prompter.ReadTOTP("2FA code: ")
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
