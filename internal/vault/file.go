package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// pbxExt is the default output extension, PRD section 6.1.
const pbxExt = ".pbx"

// ageVault is the stateless Vault implementation backed by filippo.io/age.
type ageVault struct{}

// New returns the Vault implementation for single files. Folders land with
// internal/archive and reuse the same temp-plus-rename write below.
func New() Vault { return ageVault{} }

// Lock encrypts a single file, PRD 7.3. The plaintext streams through
// age.Encrypt into a temp file in the output directory; only a clean close
// is fsynced and renamed onto the final name, so a failure leaves no partial
// output.
func (ageVault) Lock(src string, recipient string, opts LockOptions) (string, error) {
	info, err := os.Stat(src)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("folders are not supported yet: %s", src)
	}
	r, err := parseRecipient(recipient)
	if err != nil {
		return "", err
	}
	dst := opts.Out
	if dst == "" {
		dst = src + pbxExt
	}
	if !opts.Force {
		if _, err := os.Stat(dst); err == nil {
			return "", fmt.Errorf("output exists: %s (use --force to overwrite)", dst)
		}
	}

	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()

	err = writeAtomic(dst, func(w io.Writer) error {
		enc, err := age.Encrypt(w, r)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(enc, in)
		closeErr := enc.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		return "", err
	}

	if opts.RemoveOriginal {
		if err := os.Remove(src); err != nil {
			return dst, fmt.Errorf("locked to %s but could not remove original: %w", dst, err)
		}
	}
	return dst, nil
}

// Unlock decrypts a single .pbx file, PRD 7.4 steps 3-4. Every failure from
// age (wrong identity, flipped, truncated or appended bytes) is wrapped as
// ErrIntegrity and the partial output is removed.
func (ageVault) Unlock(src string, identity age.Identity, opts UnlockOptions) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()

	dst := opts.Out
	if dst == "" {
		if !strings.HasSuffix(src, pbxExt) {
			return "", fmt.Errorf("not a %s file: %s", pbxExt, src)
		}
		dst = strings.TrimSuffix(src, pbxExt)
	}
	if !opts.Force {
		if _, err := os.Stat(dst); err == nil {
			return "", fmt.Errorf("output exists: %s (use --force to overwrite)", dst)
		}
	}

	err = writeAtomic(dst, func(w io.Writer) error {
		dec, err := age.Decrypt(in, identity)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, dec)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	return dst, nil
}

// parseRecipient parses a keystore recipient string into an age.Recipient.
// vault owns all age types so keystore never imports age.
func parseRecipient(s string) (age.Recipient, error) {
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient: %w", err)
	}
	return r, nil
}

// writeAtomic runs fn against a temp file in the same directory as path,
// then fsyncs and renames it onto path with mode 0600, PRD 7.3 step 3. Any
// failure removes the temp file and leaves no partial output.
func writeAtomic(path string, fn func(w io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pillarbox-tmp-*") // CreateTemp uses mode 0600
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := fn(tmp); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
