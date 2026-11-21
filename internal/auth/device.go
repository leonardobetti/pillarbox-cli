package auth

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
)

// deviceSecretLen is 32 bytes, PRD 6.3.
const deviceSecretLen = 32

type deviceStore struct{ path string }

// NewDeviceSecretStore returns a DeviceSecretStore persisting at path.
func NewDeviceSecretStore(path string) DeviceSecretStore { return deviceStore{path: path} }

// DefaultDeviceSecretPath returns <config>/pillarbox/device.key, PRD 6.3.
func DefaultDeviceSecretPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pillarbox", "device.key"), nil
}

func (d deviceStore) Load() ([]byte, error) {
	data, err := os.ReadFile(d.path)
	if err != nil {
		return nil, err
	}
	if len(data) != deviceSecretLen {
		return nil, errors.New("device secret has wrong length")
	}
	return data, nil
}

// LoadOrCreate returns the existing device secret or creates 32 random bytes
// atomically with mode 0600, PRD 6.3 and 7.1 step 2.
func (d deviceStore) LoadOrCreate() ([]byte, bool, error) {
	if data, err := d.Load(); err == nil {
		return data, false, nil
	}
	secret := make([]byte, deviceSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, false, err
	}
	if err := writeAtomic0600(d.path, secret); err != nil {
		return nil, false, err
	}
	return secret, true, nil
}

func writeAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".device-tmp-*") // CreateTemp uses mode 0600
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
