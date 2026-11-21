package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/leonardobetti/pillarbox-cli/internal/archive"
)

// pbxExt is the default output extension for single files, PRD section 6.1.
const pbxExt = ".pbx"

// ageVault is the Vault implementation backed by filippo.io/age, with
// internal/archive streaming folders through tar.
type ageVault struct {
	w archive.Writer
	x archive.Extractor
}

// New returns the Vault implementation.
func New() Vault {
	return ageVault{w: archive.NewWriter(), x: archive.NewExtractor()}
}

// Lock encrypts src, a single file or a folder, PRD 7.3. The plaintext
// streams through age.Encrypt into a temp file in the output directory; only
// a clean close is fsynced and renamed onto the final name, so a failure
// leaves no partial output.
func (v ageVault) Lock(src string, recipient string, opts LockOptions) (string, error) {
	info, err := os.Stat(src)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return v.lockFolder(src, recipient, opts)
	}
	return v.lockFile(src, recipient, opts)
}

// Unlock decrypts src, a .pbx single file or a .tar.pbx folder archive, PRD
// 7.4. Every failure from age (wrong identity, flipped, truncated or
// appended bytes) is wrapped as ErrIntegrity and partial output is removed.
func (v ageVault) Unlock(src string, identity age.Identity, opts UnlockOptions) (string, error) {
	if strings.HasSuffix(src, tarPbxExt) {
		return v.unlockFolder(src, identity, opts)
	}
	return v.unlockFile(src, identity, opts)
}

func (v ageVault) lockFile(src, recipient string, opts LockOptions) (string, error) {
	r, err := parseRecipient(recipient)
	if err != nil {
		return "", err
	}
	dst := opts.Out
	if dst == "" {
		dst = src + pbxExt
	}
	if err := checkOutputFree(dst, opts.Force); err != nil {
		return "", err
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

func (v ageVault) unlockFile(src string, identity age.Identity, opts UnlockOptions) (string, error) {
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
	if err := checkOutputFree(dst, opts.Force); err != nil {
		return "", err
	}

	err = writeAtomic(dst, func(w io.Writer) error {
		dec, err := age.Decrypt(in, identity)
		if err != nil {
			return streamErr{err}
		}
		if _, err := io.Copy(w, dec); err != nil {
			return streamErr{err}
		}
		return nil
	})
	if err != nil {
		var se streamErr
		if errors.As(err, &se) {
			return "", fmt.Errorf("%w: %v", ErrIntegrity, se.err)
		}
		return "", err
	}
	return dst, nil
}

// checkOutputFree refuses to overwrite an existing output unless force is
// set, PRD 7.4 step 3.
func checkOutputFree(dst string, force bool) error {
	if force {
		return nil
	}
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%w: %s (use --force to overwrite)", ErrExists, dst)
	}
	return nil
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
