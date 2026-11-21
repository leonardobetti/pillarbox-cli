package archive

import (
	"errors"
	"io"
)

// ErrUnsafePath marks an archive entry that fails the PRD 7.4 step 3 checks:
// .., absolute paths, symlinks resolving outside the target, writes through a
// symlink, or unsupported entry types.
var ErrUnsafePath = errors.New("unsafe archive path")

// ErrExists marks an entry whose target already exists and Force is false,
// PRD 7.4 step 3.
var ErrExists = errors.New("path already exists")

// Writer streams a directory tree as tar entries with paths relative to
// root, PRD 7.3 step 2. It stores regular files, directories and symlinks
// (as symlinks).
type Writer interface {
	WriteTree(w io.Writer, root string) error
}

// ExtractOptions mirrors the extraction flags.
type ExtractOptions struct {
	Force bool // overwrite existing paths
}

// Extractor reads a tar stream and writes it under dir, applying the PRD 7.4
// step 3 checks to every entry.
type Extractor interface {
	Extract(r io.Reader, dir string, opts ExtractOptions) error
}
