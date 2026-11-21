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

// tarPbxExt is the default output extension for folders, PRD 7.3 step 2.
const tarPbxExt = ".tar.pbx"

// lockFolder streams a tar of the folder through age.Encrypt into
// <dir>.tar.pbx, PRD 7.3 step 2. File names and structure stay inside the
// encrypted stream (FR-04).
func (v ageVault) lockFolder(src, recipient string, opts LockOptions) (string, error) {
	r, err := parseRecipient(recipient)
	if err != nil {
		return "", err
	}
	dst := opts.Out
	if dst == "" {
		dst = src + tarPbxExt
	}
	if err := checkOutputFree(dst, opts.Force); err != nil {
		return "", err
	}

	err = writeAtomic(dst, func(w io.Writer) error {
		enc, err := age.Encrypt(w, r)
		if err != nil {
			return err
		}
		werr := v.w.WriteTree(enc, src)
		cerr := enc.Close()
		if werr != nil {
			return werr
		}
		return cerr
	})
	if err != nil {
		return "", err
	}

	if opts.RemoveOriginal {
		if err := os.RemoveAll(src); err != nil {
			return dst, fmt.Errorf("locked to %s but could not remove original: %w", dst, err)
		}
	}
	return dst, nil
}

// unlockFolder decrypts a .tar.pbx archive and extracts it into a temp
// directory that is renamed onto the final name, so a failure leaves no
// partial output, PRD 7.4 steps 3-4.
func (v ageVault) unlockFolder(src string, identity age.Identity, opts UnlockOptions) (string, error) {
	dst := opts.Out
	if dst == "" {
		dst = strings.TrimSuffix(src, tarPbxExt)
	}
	if err := checkOutputFree(dst, opts.Force); err != nil {
		return "", err
	}

	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()

	err = writeAtomicDir(dst, func(tmp string) error {
		dec, err := age.Decrypt(in, identity)
		if err != nil {
			return streamErr{err}
		}
		if err := v.x.Extract(dec, tmp, archive.ExtractOptions{Force: opts.Force}); err != nil {
			return streamErr{err}
		}
		return nil
	})
	if err != nil {
		var se streamErr
		if errors.As(err, &se) {
			if errors.Is(se.err, archive.ErrExists) {
				return "", fmt.Errorf("%w: %v", ErrExists, se.err)
			}
			return "", fmt.Errorf("%w: %v", ErrIntegrity, se.err)
		}
		return "", err
	}
	return dst, nil
}

// writeAtomicDir runs fn against a temp directory next to path, then renames
// it onto path. Any failure removes the temp directory entirely.
func writeAtomicDir(path string, fn func(dir string) error) error {
	parent := filepath.Dir(path)
	tmp, err := os.MkdirTemp(parent, ".pillarbox-tmp-*") // MkdirTemp uses mode 0700
	if err != nil {
		return err
	}
	if err := fn(tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	return nil
}
