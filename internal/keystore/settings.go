package keystore

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Settings are the user preferences persisted at
// <config>/pillarbox/settings.json, mode 0600. KeyType is the key type used
// for new files; empty means not configured yet, and the encrypt flow asks.
// AuthEncrypt requires the secret before the encrypt file picker; it defaults
// to false. Theme is the TUI colour theme id (default, dracula, catppuccin,
// jade); empty means default. Unlike the per-file keystores, settings hold no
// secret material.
type Settings struct {
	KeyType     Mode   `json:"key_type"`
	AuthEncrypt bool   `json:"auth_encrypt"`
	Theme       string `json:"theme,omitempty"`
}

// SettingsStore owns the settings file. Saves are atomic: temp file in the
// same directory, fsync, rename, mode 0600.
type SettingsStore interface {
	Path() string
	Exists() (bool, error)
	Load() (*Settings, error) // missing file returns empty Settings and nil error
	Save(*Settings) error
}

type settingsStore struct{ path string }

// NewSettingsStore returns a SettingsStore persisting at path.
func NewSettingsStore(path string) SettingsStore { return settingsStore{path: path} }

// DefaultSettingsStore returns the store at <config>/pillarbox/settings.json,
// where <config> is os.UserConfigDir().
func DefaultSettingsStore() (SettingsStore, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return NewSettingsStore(filepath.Join(dir, "pillarbox", "settings.json")), nil
}

func (s settingsStore) Path() string { return s.path }

func (s settingsStore) Exists() (bool, error) {
	_, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s settingsStore) Load() (*Settings, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return &Settings{}, nil
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(s.path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, ErrInvalid
	}
	var st Settings
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, ErrInvalid
	}
	if st.KeyType != "" && !st.KeyType.Valid() {
		return nil, ErrInvalid
	}
	return &st, nil
}

func (s settingsStore) Save(st *Settings) error {
	if st.KeyType != "" && !st.KeyType.Valid() {
		return ErrInvalid
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".settings-tmp-*") // CreateTemp uses mode 0600
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
