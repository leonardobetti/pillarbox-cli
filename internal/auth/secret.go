package auth

import (
	"errors"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

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
