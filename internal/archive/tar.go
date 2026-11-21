package archive

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type tarWriter struct{}

// NewWriter returns the tar Writer.
func NewWriter() Writer { return tarWriter{} }

// WriteTree walks root and writes one tar entry per regular file, directory
// and symlink, with paths relative to root, PRD 7.3 step 2.
func (tarWriter) WriteTree(w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		if !mode.IsRegular() && !info.IsDir() && mode&fs.ModeSymlink == 0 {
			return fmt.Errorf("unsupported file type: %s", path)
		}
		var link string
		if mode&fs.ModeSymlink != 0 {
			link, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeReg {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, f)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

type tarExtractor struct{}

// NewExtractor returns the tar Extractor.
func NewExtractor() Extractor { return tarExtractor{} }

// Extract reads a tar stream and writes it under dir, PRD 7.4 step 3.
func (tarExtractor) Extract(r io.Reader, dir string, opts ExtractOptions) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := extractEntry(tr, hdr, dir, opts); err != nil {
			return err
		}
	}
}

func extractEntry(tr *tar.Reader, hdr *tar.Header, root string, opts ExtractOptions) error {
	clean := filepath.Clean(filepath.FromSlash(hdr.Name))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %q", ErrUnsafePath, hdr.Name)
	}
	if clean == "." {
		return nil
	}
	if err := checkParents(root, clean); err != nil {
		return err
	}
	target := filepath.Join(root, clean)
	perm := os.FileMode(hdr.Mode) & 0o777

	switch hdr.Typeflag {
	case tar.TypeDir:
		if perm == 0 {
			perm = 0o755
		}
		return mkdir(target, perm, opts)
	case tar.TypeReg:
		if perm == 0 {
			perm = 0o600
		}
		return writeFile(tr, hdr, target, perm, opts)
	case tar.TypeSymlink:
		if err := checkSymlink(hdr.Linkname, root, clean); err != nil {
			return err
		}
		return makeSymlink(hdr.Linkname, target, opts)
	default:
		return fmt.Errorf("%w: entry type %d for %q", ErrUnsafePath, hdr.Typeflag, hdr.Name)
	}
}

// checkParents rejects an entry whose extracted path passes through a symlink
// or a non-directory, so nothing is ever written through a link.
func checkParents(root, clean string) error {
	parts := strings.Split(clean, string(filepath.Separator))
	cur := root
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		info, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %q passes through symlink %q", ErrUnsafePath, clean, cur)
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: parent of %q is not a directory", ErrUnsafePath, clean)
		}
	}
	return nil
}

// checkSymlink rejects absolute link targets and relative targets that
// resolve outside root, PRD 7.4 step 3.
func checkSymlink(linkname, root, clean string) error {
	if filepath.IsAbs(filepath.FromSlash(linkname)) {
		return fmt.Errorf("%w: symlink %q has absolute target %q", ErrUnsafePath, clean, linkname)
	}
	linkDir := filepath.Dir(filepath.Join(root, clean))
	resolved := filepath.Clean(filepath.Join(linkDir, filepath.FromSlash(linkname)))
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%w: symlink %q resolves outside the target", ErrUnsafePath, clean)
	}
	return nil
}

func mkdir(target string, perm fs.FileMode, opts ExtractOptions) error {
	info, err := os.Lstat(target)
	switch {
	case os.IsNotExist(err):
		return os.MkdirAll(target, perm)
	case err != nil:
		return err
	case info.IsDir():
		return nil
	case opts.Force:
		if err := os.RemoveAll(target); err != nil {
			return err
		}
		return os.MkdirAll(target, perm)
	default:
		return fmt.Errorf("%w: %s", ErrExists, target)
	}
}

func writeFile(tr *tar.Reader, hdr *tar.Header, target string, perm fs.FileMode, opts ExtractOptions) error {
	if _, err := os.Lstat(target); err == nil {
		if !opts.Force {
			return fmt.Errorf("%w: %s", ErrExists, target)
		}
		if err := os.RemoveAll(target); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(f, tr, hdr.Size)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func makeSymlink(linkname, target string, opts ExtractOptions) error {
	if _, err := os.Lstat(target); err == nil {
		if !opts.Force {
			return fmt.Errorf("%w: %s", ErrExists, target)
		}
		if err := os.RemoveAll(target); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(linkname, target)
}
