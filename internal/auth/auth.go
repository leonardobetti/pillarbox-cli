package auth

import (
	"errors"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

// ErrAuth is the only error an authentication flow reports to its caller. The
// message is identical for a wrong secret and a wrong TOTP code, PRD 7.4
// step 1 and FR-07, and it never contains secret material.
var ErrAuth = errors.New("authentication failed")

// SecretPrompter is the input seam between cli/tui and the user. PRD section 5
// requires no-echo input (golang.org/x/term) and section 8.3 requires
// --secret-stdin and --totp for scripts. Secrets never appear in argv, logs
// or errors, so prompts return values that errors must not echo.
type SecretPrompter interface {
	ReadSecret(prompt string) ([]byte, error)
	// ReadSecretTwice prompts and asks for confirmation, init, PRD 7.1 step 2.
	ReadSecretTwice(prompt string) ([]byte, error)
	ReadTOTP(prompt string) (string, error)
}

// KDF derives the key-encryption key, PRD 7.1 step 3:
// ikm = Argon2id(secret, salt, params), then
// kek = HKDF-SHA256(ikm, salt = deviceSecret or empty, info = pillarbox/kek/v1).
type KDF interface {
	DeriveKEK(secret, salt, deviceSecret []byte, p keystore.Argon2Params) ([]byte, error)
}

// DeviceSecretStore owns <config>/pillarbox/device.key, PRD section 6.3:
// 32 random bytes, mode 0600, created on first PIN-mode init.
type DeviceSecretStore interface {
	// Load reads the existing device secret; it fails when the file is
	// missing or has the wrong length.
	Load() ([]byte, error)
	LoadOrCreate() (secret []byte, created bool, err error)
}

// TOTPSeedStore owns <config>/pillarbox/totp.seed: one 20-byte seed for every
// 2FA file on this install. The authenticator QR is shown once, then reused.
type TOTPSeedStore interface {
	Path() string
	Exists() (bool, error)
	Load() ([]byte, error)
	Save(seed []byte) error
}

// TOTP is RFC 6238 TOTP, PRD sections 6.4, 7.1 step 5 and 7.4 step 2.
type TOTP interface {
	GenerateSeed() (seed []byte, otpauthURI string, err error)
	// Verify accepts the current step and one step either side and rejects a
	// step equal to lastStep (replay, FR-08). Returns the step to persist.
	Verify(seed []byte, code string, lastStep int64) (ok bool, newStep int64, err error)
}

// Result holds the decrypted metadata returned by Authenticator.Authenticate.
type Result struct {
	Identity     []byte
	OriginalName string // restored basename when WrappedName was stored; empty for legacy .pbx
	NewTOTPStep  int64
}

// Authenticator is the single call cli and tui make to unlock, PRD 7.4 steps
// 1-2. It derives the KEK, unwraps the identity and, for 2FA modes, verifies
// the code. On success it returns the raw age identity bytes, the restored
// original filename (when stored), and the TOTP step to persist; the caller
// stores the step through keystore.Store, the only writer of the keystore. A
// failed unwrap or a wrong code returns ErrAuth and says nothing about which
// factor failed.
type Authenticator interface {
	Authenticate(ks *keystore.Keystore, secret []byte, totpCode string) (Result, error)
}

// Initializer builds a new keystore, PRD 7.1: it derives the KEK from the
// secret and wraps the identity (plus the TOTP seed for 2FA modes, and the
// original basename when provided) under it. identity is the raw age secret
// key bytes; it is never stored in the clear.
type Initializer interface {
	Initialize(mode keystore.Mode, recipient string, identity, secret, deviceSecret, totpSeed []byte, params keystore.Argon2Params, origName string) (*keystore.Keystore, error)
}
