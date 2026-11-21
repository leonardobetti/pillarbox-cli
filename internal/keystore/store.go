package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type fileStore struct{ path string }

// NewStore returns a Store persisting the keystore at path.
func NewStore(path string) Store { return fileStore{path: path} }

// DefaultStore returns a Store at <config>/pillarbox/keystore.json, where
// <config> is os.UserConfigDir(), PRD 7.1 step 6.
func DefaultStore() (Store, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return NewStore(filepath.Join(dir, "pillarbox", "keystore.json")), nil
}

func (s fileStore) Path() string { return s.path }

func (s fileStore) Exists() (bool, error) {
	_, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Load reads and validates the keystore. It never returns secret material in
// errors; only schema problems are reported.
func (s fileStore) Load() (*Keystore, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(s.path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: permissions %o are too open", ErrInvalid, perm)
	}
	var ks Keystore
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("%w: malformed keystore file", ErrInvalid)
	}
	if err := ks.validate(); err != nil {
		return nil, err
	}
	return &ks, nil
}

// validate checks the schema of section 7.2. It must not echo secret fields.
func (ks *Keystore) validate() error {
	if ks.Version != 1 {
		return fmt.Errorf("%w: unsupported version", ErrInvalid)
	}
	if !ks.Mode.Valid() {
		return fmt.Errorf("%w: unknown mode", ErrInvalid)
	}
	if len(ks.Salt) != 16 {
		return fmt.Errorf("%w: bad salt length", ErrInvalid)
	}
	if ks.Recipient == "" {
		return fmt.Errorf("%w: missing recipient", ErrInvalid)
	}
	if len(ks.WrappedIdentity.Nonce) != 24 || len(ks.WrappedIdentity.Ciphertext) == 0 {
		return fmt.Errorf("%w: missing wrapped identity", ErrInvalid)
	}
	if ks.Mode.Has2FA() && ks.WrappedTOTPSeed == nil {
		return fmt.Errorf("%w: 2FA mode without wrapped TOTP seed", ErrInvalid)
	}
	return nil
}

// Save writes the keystore atomically: temp file in the same directory,
// fsync, rename, mode 0600, PRD 7.1 step 6.
func (s fileStore) Save(ks *Keystore) error {
	if err := ks.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".keystore-tmp-*") // CreateTemp uses mode 0600
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
	if err := os.Rename(name, s.path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
