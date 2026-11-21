package keystore

import (
	"errors"
	"time"
)

// Mode is an unlock mode, PRD section 6.2. The string values are persisted in
// keystore.json and must stay stable. The PIN modes mix a device secret into
// the key (section 6.3); the 2FA modes verify a TOTP code (section 6.4).
type Mode string

const (
	ModePassword    Mode = "password"
	ModePIN         Mode = "pin"
	ModePassword2FA Mode = "password+2fa"
	ModePIN2FA      Mode = "pin+2fa"
)

// Valid reports whether m is one of the four unlock modes, PRD 6.2.
func (m Mode) Valid() bool {
	switch m {
	case ModePassword, ModePIN, ModePassword2FA, ModePIN2FA:
		return true
	}
	return false
}

// Has2FA reports whether the mode verifies a TOTP code, PRD 6.2.
func (m Mode) Has2FA() bool { return m == ModePassword2FA || m == ModePIN2FA }

// HasDeviceSecret reports whether the mode mixes the device secret into the
// KEK, PRD 6.3.
func (m Mode) HasDeviceSecret() bool { return m == ModePIN || m == ModePIN2FA }

// Argon2Params are the Argon2id parameters, PRD section 7.1 step 3. They live
// in the keystore so a later version can raise them, PRD section 7.2.
type Argon2Params struct {
	Time    uint32 `json:"time"`    // t, iterations
	Memory  uint32 `json:"memory"`  // m, in KiB
	Threads uint8  `json:"threads"` // p
}

// DefaultArgon2Params are the v0.1 values: t=3, m=64 MiB, p=4 (PRD 7.1 step 3).
var DefaultArgon2Params = Argon2Params{Time: 3, Memory: 64 * 1024, Threads: 4}

// WrappedKey is a value sealed with XChaCha20-Poly1305: 24-byte random nonce
// plus ciphertext, PRD sections 7.1 step 4 and 7.2.
type WrappedKey struct {
	Nonce      []byte `json:"nonce"`      // base64 in JSON
	Ciphertext []byte `json:"ciphertext"` // base64 in JSON
}

// Policy holds user settings, PRD section 7.2.
type Policy struct {
	// GateEncrypt makes lock authenticate first when true, PRD 7.3 step 1.
	GateEncrypt bool `json:"gate_encrypt"`
}

// Keystore is the on-disk schema at <config>/pillarbox/keystore.json, PRD
// section 7.2. Recipient is the age public key as a string; the identity
// itself stays wrapped and is never stored in the clear.
type Keystore struct {
	Version         int          `json:"version"`
	Mode            Mode         `json:"mode"`
	Argon2          Argon2Params `json:"argon2"`
	Salt            []byte       `json:"salt"` // 16 random bytes, base64 in JSON, PRD 7.1 step 3
	Recipient       string       `json:"recipient"`
	WrappedIdentity WrappedKey   `json:"wrapped_identity"`
	WrappedTOTPSeed *WrappedKey  `json:"wrapped_totp_seed,omitempty"` // 2FA modes only
	LastTOTPStep    *int64       `json:"last_totp_step,omitempty"`    // 2FA modes only, replay protection, PRD 7.2
	Policy          Policy       `json:"policy"`
	CreatedAt       time.Time    `json:"created_at"`
}

// Sentinel errors. cli maps them to exit codes, PRD section 9.
var (
	ErrNotFound = errors.New("keystore not found")
	ErrInvalid  = errors.New("keystore invalid")
)

// Store owns the keystore file. One keystore per user and the Store is its
// only writer, so saves are serialized and atomic: temp file in the same
// directory, fsync, rename, mode 0600, PRD 7.1 step 6.
type Store interface {
	Path() string
	Exists() (bool, error)
	Load() (*Keystore, error) // returns ErrNotFound or ErrInvalid
	Save(ks *Keystore) error
}

// Wrapper seals and unseals values under a KEK with XChaCha20-Poly1305, PRD
// sections 7.1 steps 4-5. The associated data is the keystore version, mode
// and recipient, so a wrapped value cannot be replayed across keystores.
// Callers must treat any Unwrap error as an authentication failure and must
// not report which factor failed, PRD 7.4 step 1.
type Wrapper interface {
	Wrap(kek []byte, ks *Keystore, plaintext []byte) (WrappedKey, error)
	Unwrap(kek []byte, ks *Keystore, w WrappedKey) ([]byte, error)
}
