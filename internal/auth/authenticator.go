package auth

import (
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
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
// verifies the TOTP code. When the keystore carries a wrapped original
// filename it is unwrapped and validated after authentication succeeds. Every
// failure that depends on the secret or the code returns the fixed ErrAuth;
// errors never contain secret material and never say which factor failed,
// PRD 7.4 step 1 and FR-07.
func (a authenticator) Authenticate(ks *keystore.Keystore, secret []byte, totpCode string) (Result, error) {
	var deviceSecret []byte
	if ks.Mode.HasDeviceSecret() {
		if a.dev == nil {
			return Result{}, ErrAuth
		}
		ds, err := a.dev.Load()
		if err != nil {
			// PIN modes decrypt only on a machine with the device secret or
			// with the recovery key, PRD 6.3.
			return Result{}, ErrAuth
		}
		deviceSecret = ds
		defer clear(deviceSecret)
	}

	kek, err := a.kdf.DeriveKEK(secret, ks.Salt, deviceSecret, ks.Argon2)
	if err != nil {
		return Result{}, err
	}
	defer clear(kek)

	identity, err := a.wrap.Unwrap(kek, ks, ks.WrappedIdentity)
	if err != nil {
		return Result{}, ErrAuth
	}

	var newStep int64
	if ks.Mode.Has2FA() {
		if ks.WrappedTOTPSeed == nil {
			clear(identity)
			return Result{}, ErrAuth
		}
		seed, err := a.wrap.Unwrap(kek, ks, *ks.WrappedTOTPSeed)
		if err != nil {
			clear(identity)
			return Result{}, ErrAuth
		}
		defer clear(seed)

		last := int64(-1)
		if ks.LastTOTPStep != nil {
			last = *ks.LastTOTPStep
		}
		ok, step, err := a.totp.Verify(seed, totpCode, last)
		if err != nil {
			clear(identity)
			return Result{}, err
		}
		if !ok {
			clear(identity)
			return Result{}, ErrAuth
		}
		newStep = step
	}

	origName := ""
	if ks.WrappedName != nil {
		rawName, err := a.wrap.Unwrap(kek, ks, *ks.WrappedName)
		if err != nil {
			clear(identity)
			return Result{}, ErrAuth
		}
		name := string(rawName)
		if !isSafeBaseName(name) {
			clear(identity)
			return Result{}, ErrAuth
		}
		origName = name
	}

	return Result{
		Identity:     identity,
		OriginalName: origName,
		NewTOTPStep:  newStep,
	}, nil
}

// isSafeBaseName reports whether name is a single filename component with no
// path separators, NUL bytes, or traversal segments.
func isSafeBaseName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	return filepath.Base(name) == name
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
// identity wrapped under the KEK, the TOTP seed wrapped for 2FA modes, and
// the original basename wrapped when origName is non-empty. identity is the
// raw age secret key bytes and is never stored in the clear.
func (i initializer) Initialize(mode keystore.Mode, recipient string, identity, secret, deviceSecret, totpSeed []byte, params keystore.Argon2Params, origName string) (*keystore.Keystore, error) {
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
	if origName != "" {
		base := filepath.Base(origName)
		if !isSafeBaseName(base) {
			return nil, errors.New("invalid original filename")
		}
		wn, err := i.wrap.Wrap(kek, ks, []byte(base))
		if err != nil {
			return nil, err
		}
		ks.WrappedName = &wn
	}
	return ks, nil
}
