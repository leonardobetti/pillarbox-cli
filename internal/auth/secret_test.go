package auth

import (
	"strings"
	"testing"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

func TestSecretRulesMatchValidation(t *testing.T) {
	for _, m := range []keystore.Mode{keystore.ModePassword, keystore.ModePIN, keystore.ModePassword2FA, keystore.ModePIN2FA} {
		rules := SecretRules(m)
		if len(rules) == 0 {
			t.Fatalf("mode %s: no rules", m)
		}
		joined := strings.Join(rules, " ")
		if m.HasDeviceSecret() {
			if !strings.Contains(joined, "6 to 12 digits") {
				t.Errorf("mode %s: rules %q do not state the PIN length rule", m, joined)
			}
		} else if !strings.Contains(joined, "at least 12 characters") {
			t.Errorf("mode %s: rules %q do not state the passphrase length rule", m, joined)
		}
		if m.Has2FA() && (!strings.Contains(joined, "TOTP") || !strings.Contains(joined, "One authenticator")) {
			t.Errorf("mode %s: rules %q do not mention the 2FA code", m, joined)
		}
	}
}
