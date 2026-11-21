package vault

import (
	"errors"

	"filippo.io/age"
)

// ErrIntegrity marks a failed authenticity check on a .pbx file or an unsafe
// archive entry. The implementation must remove partial output before
// returning it, PRD 7.4 step 4. cli maps it to exit code 4.
var ErrIntegrity = errors.New("integrity failure")

// ErrExists marks an output path that already exists without --force, PRD
// 7.4 step 3. cli maps it to exit code 2.
var ErrExists = errors.New("output exists")

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
	Out            string // -o; default <name>.pbx for a file, <dir>.tar.pbx for a folder
	RemoveOriginal bool   // --remove-original
	Force          bool   // --force
}

// UnlockOptions mirrors the unlock flags, PRD section 9.
type UnlockOptions struct {
	Out   string // -o
	Force bool   // overwrite existing paths
}

// Vault runs the lock and unlock pipelines, PRD sections 7.3 and 7.4: age
// streaming, tar for folders, temp file + fsync + rename with mode 0600.
// Vault owns the output files; no other package writes them.
type Vault interface {
	// Lock encrypts src, a file or a folder, under recipient (the keystore
	// recipient string, parsed here so keystore never imports age). A folder
	// becomes a tar stream with names inside the encrypted payload. A
	// failure leaves no partial output. Returns the output path.
	Lock(src string, recipient string, opts LockOptions) (dst string, err error)
	// Unlock decrypts src with identity and extracts it. Archive entries with
	// .., absolute paths or symlinks resolving outside the target are
	// rejected, existing paths are not overwritten without Force, and any
	// tampering returns ErrIntegrity with no partial output left behind.
	Unlock(src string, identity age.Identity, opts UnlockOptions) (dst string, err error)
}
