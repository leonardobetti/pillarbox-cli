package auth

import (
	"errors"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

// SecretRules returns the requirements for the secret of a mode, shown before
// the user types so a rejected secret is never a surprise. Keep in sync with
// ValidateSecret.
func SecretRules(m keystore.Mode) []string {
	rules := []string{}
	if m.HasDeviceSecret() {
		rules = append(rules, "PIN: 6 to 12 digits, numbers only.")
	} else {
		rules = append(rules,
			"Passphrase: at least 12 characters.",
			"You need 12 characters minimum because every extra character multiplies the guesses an attacker must make, and Argon2id makes each guess take about half a second.",
		)
	}
	if m.Has2FA() {
		rules = append(rules,
			"Plus a 6-digit TOTP code from your authenticator app at every unlock.",
			"One authenticator entry covers every 2FA file on this install.",
		)
	}
	return rules
}

// ValidateSecret enforces the PRD 6.2 length rules: a passphrase is 12
// characters or more, a PIN is 6 to 12 digits. The error never contains the
// secret.
func ValidateSecret(m keystore.Mode, s []byte) error {
	if m.HasDeviceSecret() {
		if len(s) < 6 || len(s) > 12 {
			return errors.New("PIN must be 6 to 12 digits")
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return errors.New("PIN must be digits only")
			}
		}
		return nil
	}
	if len(s) < 12 {
		return errors.New("passphrase must be at least 12 characters")
	}
	return nil
}
