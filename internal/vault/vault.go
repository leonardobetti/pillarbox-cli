package vault

import (
	"errors"

	"filippo.io/age"

	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

// ErrIntegrity marks a failed authenticity check on a .pbx file or an unsafe
// archive entry. The implementation must remove partial output before
// returning it, PRD 7.4 step 4. cli maps it to exit code 4.
var ErrIntegrity = errors.New("integrity failure")

// ErrExists marks an output path that already exists without --force, PRD
// 7.4 step 3. cli maps it to exit code 2.
var ErrExists = errors.New("output exists")

// ErrUnsupported marks a folder path or .tar.pbx archive. Pillarbox encrypts
// single files only; cli maps it to exit code 2.
var ErrUnsupported = errors.New("folders are not supported")

// streamErr marks an error raised inside the decrypt/extract callback as a
// stream failure. Infrastructure errors from writeAtomic itself (temp file
// creation, fsync, rename) stay plain I/O errors, so cli never reports an
// unwritable output directory as an integrity failure (exit code 4 is
// reserved for actual tampering, PRD section 9).
type streamErr struct{ err error }

func (e streamErr) Error() string { return e.err.Error() }
func (e streamErr) Unwrap() error { return e.err }

// LockOptions mirrors the lock flags, PRD section 9.
type LockOptions struct {
	Out            string // -o; default <stem>.pbx (auto-suffixed on collision unless Force)
	RemoveOriginal bool   // --remove-original
	Force          bool   // --force
}

// UnlockOptions mirrors the unlock flags, PRD section 9.
type UnlockOptions struct {
	Out          string // -o
	OriginalName string // restored basename from keystore (ignored when Out is set)
	Force        bool   // overwrite existing paths
}

// Vault runs the lock and unlock pipelines for single files, PRD sections
// 7.3 and 7.4: age streaming, temp file + fsync + rename with mode 0600.
// Vault owns the output files; no other package writes them.
type Vault interface {
	// Lock encrypts src, a single file, into one self-contained .pbx: a PBX1
	// header line carrying the file's key (the serialized keystore), followed
	// by the age stream to the key's recipient. Folders return
	// ErrUnsupported. A failure leaves no partial output. Returns the output
	// path.
	Lock(src string, ks *keystore.Keystore, opts LockOptions) (dst string, err error)
	// Unlock decrypts src with identity, skipping the PBX1 header when
	// present. Existing paths are not overwritten without Force, and any
	// tampering returns ErrIntegrity with no partial output left behind.
	Unlock(src string, identity age.Identity, opts UnlockOptions) (dst string, err error)
	// ReadKey returns the file's key from a .pbx: the PBX1 header, or, for
	// files written by v0.2.0, the <file>.pbx.key sidecar.
	ReadKey(src string) (*keystore.Keystore, error)
	// SaveKey rewrites the PBX1 header of src with ks, keeping the encrypted
	// payload byte for byte. Used to persist the TOTP step after unlock.
	SaveKey(src string, ks *keystore.Keystore) error
}
