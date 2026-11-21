package auth

import (
	"crypto/rand"
	"errors"
	"time"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

type authenticator struct {
	kdf  KDF
	wrap keystore.Wrapper
	dev  DeviceSecretStore
	totp TOTP
}

// NewAuthenticator wires the unlock flow of PRD 7.4 steps 1-2.
func NewAuthenticator(kdf KDF, wrap keystore.Wrapper, dev DeviceSecretStore, totp TOTP) Authenticator {
	return authenticator{kdf: kdf, wrap: wrap, dev: dev, totp: totp}
}

// Authenticate derives the KEK, unwraps the identity and, for 2FA modes,
// verifies the TOTP code. Every failure that depends on the secret or the
// code returns the fixed ErrAuth; errors never contain secret material and
// never say which factor failed, PRD 7.4 step 1 and FR-07.
func (a authenticator) Authenticate(ks *keystore.Keystore, secret []byte, totpCode string) ([]byte, int64, error) {
	var deviceSecret []byte
	if ks.Mode.HasDeviceSecret() {
		if a.dev == nil {
			return nil, 0, ErrAuth
		}
		ds, err := a.dev.Load()
		if err != nil {
			// PIN modes decrypt only on a machine with the device secret or
			// with the recovery key, PRD 6.3.
			return nil, 0, ErrAuth
		}
		deviceSecret = ds
		defer clear(deviceSecret)
	}

	kek, err := a.kdf.DeriveKEK(secret, ks.Salt, deviceSecret, ks.Argon2)
	if err != nil {
		return nil, 0, err
	}
	defer clear(kek)

	identity, err := a.wrap.Unwrap(kek, ks, ks.WrappedIdentity)
	if err != nil {
		return nil, 0, ErrAuth
	}
	if !ks.Mode.Has2FA() {
		return identity, 0, nil
	}

	if ks.WrappedTOTPSeed == nil {
		return nil, 0, ErrAuth
	}
	seed, err := a.wrap.Unwrap(kek, ks, *ks.WrappedTOTPSeed)
	if err != nil {
		return nil, 0, ErrAuth
	}
	defer clear(seed)

	last := int64(-1)
	if ks.LastTOTPStep != nil {
		last = *ks.LastTOTPStep
	}
	ok, newStep, err := a.totp.Verify(seed, totpCode, last)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		return nil, 0, ErrAuth
	}
	return identity, newStep, nil
}

type initializer struct {
	kdf  KDF
	wrap keystore.Wrapper
}

// NewInitializer wires the init flow of PRD 7.1.
func NewInitializer(kdf KDF, wrap keystore.Wrapper) Initializer {
	return initializer{kdf: kdf, wrap: wrap}
}

// Initialize builds a new keystore: fresh 16-byte salt, KEK from the secret,
// identity wrapped under the KEK, and for 2FA modes the TOTP seed wrapped the
// same way. identity is the raw age secret key bytes and is never stored in
// the clear.
func (i initializer) Initialize(mode keystore.Mode, recipient string, identity, secret, deviceSecret, totpSeed []byte, params keystore.Argon2Params) (*keystore.Keystore, error) {
	if !mode.Valid() {
		return nil, errors.New("invalid mode")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	kek, err := i.kdf.DeriveKEK(secret, salt, deviceSecret, params)
	if err != nil {
		return nil, err
	}
	defer clear(kek)

	ks := &keystore.Keystore{
		Version:   1,
		Mode:      mode,
		Argon2:    params,
		Salt:      salt,
		Recipient: recipient,
		CreatedAt: time.Now().UTC(),
	}
	w, err := i.wrap.Wrap(kek, ks, identity)
	if err != nil {
		return nil, err
	}
	ks.WrappedIdentity = w
	if mode.Has2FA() {
		ws, err := i.wrap.Wrap(kek, ks, totpSeed)
		if err != nil {
			return nil, err
		}
		ks.WrappedTOTPSeed = &ws
	}
	return ks, nil
}
