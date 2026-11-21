package auth

import (
	"errors"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

// SecretRules returns the requirements for the secret of a mode, shown before
// the user types so a rejected secret is never a surprise. Each rule carries
// the reason it exists, PRD sections 6.2 and 6.3. Keep in sync with
// ValidateSecret.
func SecretRules(m keystore.Mode) []string {
	rules := []string{}
	if m.HasDeviceSecret() {
		rules = append(rules,
			"PIN: 6 to 12 digits, numbers only.",
			"You need 6 digits minimum because a 6-digit PIN has only 1,000,000 values, about six days of guessing on one core at this Argon2id cost.",
			"You need the device secret too: PIN modes mix a 32-byte secret from this machine into the key, so the PIN alone only protects you if someone copies your whole config folder.",
		)
	} else {
		rules = append(rules,
			"Passphrase: at least 12 characters.",
			"You need 12 characters minimum because every extra character multiplies the guesses an attacker must make, and Argon2id makes each guess take about half a second.",
		)
	}
	if m.Has2FA() {
		rules = append(rules, "Plus a 6-digit TOTP code from your authenticator app at every unlock.")
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
