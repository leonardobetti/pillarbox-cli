package vault

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

// pbxExt is the default output extension for single files, PRD section 6.1.
const pbxExt = ".pbx"

// headerMagic prefixes the first line of a single-file .pbx. The line is
// "PBX1 <base64 JSON keystore>\n", and the age payload follows byte for byte.
// The payload itself is a standard age file, so the recovery key still
// decrypts it after stripping the first line.
const headerMagic = "PBX1 "

// ageVault is the Vault implementation backed by filippo.io/age.
type ageVault struct{}

// New returns the Vault implementation.
func New() Vault {
	return ageVault{}
}

// Lock encrypts src, a single file, into one self-contained .pbx: PBX1 header
// line plus the age stream. The plaintext streams into a temp file in the
// output directory; only a clean close is fsynced and renamed, so a failure
// leaves no partial output. Folders return ErrUnsupported.
func (v ageVault) Lock(src string, ks *keystore.Keystore, opts LockOptions) (string, error) {
	info, err := os.Stat(src)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", ErrUnsupported
	}
	return v.lockFile(src, ks, opts)
}

// Unlock decrypts src with identity, skipping the PBX1 header line when
// present. Every failure from age (wrong identity, flipped, truncated or
// appended bytes) is wrapped as ErrIntegrity and partial output is removed.
// Folder archives return ErrUnsupported.
func (v ageVault) Unlock(src string, identity age.Identity, opts UnlockOptions) (string, error) {
	if strings.HasSuffix(src, ".tar.pbx") {
		return "", ErrUnsupported
	}
	return v.unlockFile(src, identity, opts)
}

// ReadKey returns the file's key: the PBX1 header of a single-file .pbx, or
// the <file>.pbx.key sidecar written by v0.2.0.
func (v ageVault) ReadKey(src string) (*keystore.Keystore, error) {
	in, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer func() { _ = in.Close() }()
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if strings.HasPrefix(line, headerMagic) {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, headerMagic)))
		if err != nil {
			return nil, fmt.Errorf("%w: bad PBX1 header", keystore.ErrInvalid)
		}
		ks, err := keystore.Parse(raw)
		if err != nil {
			return nil, err
		}
		return ks, nil
	}
	// v0.2.0 two-file format: key in the sidecar.
	return keystore.NewStore(src + ".key").Load()
}

// SaveKey rewrites the PBX1 header of src with ks and copies the encrypted
// payload unchanged, atomically via temp file + rename.
func (v ageVault) SaveKey(src string, ks *keystore.Keystore) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	br := bufio.NewReader(in)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, headerMagic) {
		return fmt.Errorf("%w: not a single-file .pbx", keystore.ErrInvalid)
	}
	meta, err := json.Marshal(ks)
	if err != nil {
		return err
	}
	header := headerMagic + base64.StdEncoding.EncodeToString(meta) + "\n"
	return writeAtomic(src, func(w io.Writer) error {
		if _, err := io.WriteString(w, header); err != nil {
			return err
		}
		_, err := io.Copy(w, br)
		return err
	})
}

// Stem strips everything from the first non-leading dot in a filename so that
// extensions (including compound ones like .tar.gz) are hidden on disk while
// dotfiles such as .env keep their leading dot intact.
func Stem(base string) string {
	if len(base) <= 1 {
		return base
	}
	if idx := strings.IndexByte(base[1:], '.'); idx >= 0 {
		return base[:idx+1]
	}
	return base
}

// DefaultLockPath computes the default .pbx path for src by stripping its
// extension(s) to hide the original file format (e.g. alice.jpg -> alice.pbx,
// backup.tar.gz -> backup.pbx, .env -> .env.pbx). When force is false and the
// default path already exists, it auto-suffixes (-2, -3, ...) to avoid
// colliding with another file sharing the same stem.
func DefaultLockPath(src string, force bool) (string, error) {
	dir := filepath.Dir(src)
	stem := Stem(filepath.Base(src))
	base := filepath.Join(dir, stem+pbxExt)
	if force {
		return base, nil
	}
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return base, nil
	} else if err != nil {
		return "", err
	}
	for n := 2; n < 100000; n++ {
		cand := filepath.Join(dir, fmt.Sprintf("%s-%d%s", stem, n, pbxExt))
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("%w: could not find free output name for %s", ErrExists, base)
}

// DefaultUnlockPath returns the default output path for decrypting src. When
// origName is non-empty (restored from a wrapped filename in the keystore),
// it is validated as a safe single basename and placed beside src. Otherwise
// (legacy .pbx without a wrapped filename), the trailing .pbx suffix is
// stripped.
func DefaultUnlockPath(src, origName string) (string, error) {
	if origName != "" {
		if origName == "." || origName == ".." || strings.ContainsAny(origName, "/\\\x00") || filepath.Base(origName) != origName {
			return "", fmt.Errorf("%w: invalid stored filename", ErrIntegrity)
		}
		return filepath.Join(filepath.Dir(src), origName), nil
	}
	if !strings.HasSuffix(src, pbxExt) {
		return "", fmt.Errorf("not a %s file: %s", pbxExt, src)
	}
	return strings.TrimSuffix(src, pbxExt), nil
}

func (v ageVault) lockFile(src string, ks *keystore.Keystore, opts LockOptions) (string, error) {
	r, err := parseRecipient(ks.Recipient)
	if err != nil {
		return "", err
	}
	dst := opts.Out
	if dst != "" {
		if err := checkOutputFree(dst, opts.Force); err != nil {
			return "", err
		}
	} else {
		dst, err = DefaultLockPath(src, opts.Force)
		if err != nil {
			return "", err
		}
	}

	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()

	meta, err := json.Marshal(ks)
	if err != nil {
		return "", err
	}
	header := headerMagic + base64.StdEncoding.EncodeToString(meta) + "\n"

	err = writeAtomic(dst, func(w io.Writer) error {
		if _, err := io.WriteString(w, header); err != nil {
			return err
		}
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
		dst, err = DefaultUnlockPath(src, opts.OriginalName)
		if err != nil {
			return "", err
		}
	}
	if err := checkOutputFree(dst, opts.Force); err != nil {
		return "", err
	}

	// Skip the PBX1 header line when present; otherwise the whole stream is
	// the age payload (v0.2.0 sidecar format).
	br := bufio.NewReader(in)
	payload := io.Reader(br)
	if line, lerr := br.ReadString('\n'); lerr == nil && strings.HasPrefix(line, headerMagic) {
		payload = br
	} else {
		payload = io.MultiReader(strings.NewReader(line), br)
	}

	err = writeAtomic(dst, func(w io.Writer) error {
		dec, err := age.Decrypt(payload, identity)
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
