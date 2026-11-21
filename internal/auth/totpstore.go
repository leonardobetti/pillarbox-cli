package auth

import (
	"errors"
	"os"
	"path/filepath"
)

// totpSeedLen is 20 bytes, matching GenerateSeed.
const totpSeedLen = 20

// totpSeedStore persists the install-wide TOTP seed at path.
type totpSeedStore struct{ path string }

// NewTOTPSeedStore returns a TOTPSeedStore that persists at path.
func NewTOTPSeedStore(path string) TOTPSeedStore { return totpSeedStore{path: path} }

// DefaultTOTPSeedPath returns <config>/pillarbox/totp.seed.
func DefaultTOTPSeedPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pillarbox", "totp.seed"), nil
}

func (s totpSeedStore) Path() string { return s.path }

func (s totpSeedStore) Exists() (bool, error) {
	_, err := os.Stat(s.path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (s totpSeedStore) Load() ([]byte, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	if len(data) != totpSeedLen {
		return nil, errors.New("TOTP seed has wrong length")
	}
	return data, nil
}

func (s totpSeedStore) Save(seed []byte) error {
	if len(seed) != totpSeedLen {
		return errors.New("TOTP seed has wrong length")
	}
	return writeAtomic0600(s.path, seed)
}
