// Package casv11 implements the Awesome-OS unified v11 content-addressed
// storage (CAS) build-cache intersection for Go build artifacts.
//
// Layout:
//
//	<root>/v11/files/<sha512[:2]>/<sha512>[-exec]
package casv11

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// B8GAbiMagicV3 is the canonical B8G ABI v3 magic word ("B8G3" LE).
const B8GAbiMagicV3 = uint32(0x33564742)

// StoreLayoutVersion is the CAS directory layout version.
const StoreLayoutVersion = "v11"

// ErrInvalidDigest is returned when a digest is not a 128-character lowercase hex SHA-512 string.
var ErrInvalidDigest = errors.New("casv11: invalid sha512 hex digest")

// ErrIntegrityMismatch is returned when stored content does not match its expected SHA-512 digest.
var ErrIntegrityMismatch = errors.New("casv11: content integrity mismatch")

// Store manages a v11 content-addressed artifact store on the local filesystem.
type Store struct {
	Root string
}

// NewStore returns a Store rooted at root.
func NewStore(root string) *Store {
	return &Store{Root: root}
}

// DigestBytes computes the lowercase hex SHA-512 digest of data.
func DigestBytes(data []byte) string {
	sum := sha512.Sum512(data)
	return hex.EncodeToString(sum[:])
}

// ValidateDigest verifies that digest is a valid 128-character lowercase hex SHA-512 string.
func ValidateDigest(digest string) error {
	if len(digest) != sha512.Size*2 {
		return fmt.Errorf("%w: got length %d, want %d", ErrInvalidDigest, len(digest), sha512.Size*2)
	}
	for i := 0; i < len(digest); i++ {
		c := digest[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("%w: invalid char %q at index %d", ErrInvalidDigest, c, i)
		}
	}
	return nil
}

// ObjectPath returns the canonical v11 path:
//
//	<root>/v11/files/<sha512[:2]>/<sha512>[-exec]
func (s *Store) ObjectPath(digest string, exec bool) (string, error) {
	if err := ValidateDigest(digest); err != nil {
		return "", err
	}
	name := digest
	if exec {
		name += "-exec"
	}
	return filepath.Join(s.Root, StoreLayoutVersion, "files", digest[:2], name), nil
}

// Put stores data in the v11 CAS and returns its SHA-512 hex digest and canonical path.
// Existing identical objects are deduplicated without rewriting.
func (s *Store) Put(data []byte, exec bool) (string, string, error) {
	digest := DigestBytes(data)
	dst, err := s.ObjectPath(digest, exec)
	if err != nil {
		return "", "", err
	}

	if _, err := os.Stat(dst); err == nil {
		return digest, dst, nil
	}

	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("casv11: mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".casv11-tmp-*")
	if err != nil {
		return "", "", fmt.Errorf("casv11: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", "", fmt.Errorf("casv11: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", "", fmt.Errorf("casv11: close temp: %w", err)
	}

	mode := os.FileMode(0o644)
	if exec {
		mode = 0o755
	}
	_ = os.Chmod(tmpName, mode)

	if err := os.Rename(tmpName, dst); err != nil {
		// Handle concurrent writer race cleanly (especially on Windows).
		if _, statErr := os.Stat(dst); statErr == nil {
			return digest, dst, nil
		}
		return "", "", fmt.Errorf("casv11: rename to %s: %w", dst, err)
	}
	cleanup = false
	return digest, dst, nil
}

// PutFile reads a build artifact from srcPath and stores it in the v11 CAS.
func (s *Store) PutFile(srcPath string, exec bool) (string, string, error) {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return "", "", fmt.Errorf("casv11: read %s: %w", srcPath, err)
	}
	return s.Put(data, exec)
}

// Get retrieves the artifact bytes for digest from the v11 CAS.
func (s *Store) Get(digest string, exec bool) ([]byte, error) {
	path, err := s.ObjectPath(digest, exec)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("casv11: get %s: %w", digest, err)
	}
	return data, nil
}

// Has reports whether the artifact exists in the v11 CAS.
func (s *Store) Has(digest string, exec bool) bool {
	path, err := s.ObjectPath(digest, exec)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// Verify checks that the stored object matches its SHA-512 digest.
func (s *Store) Verify(digest string, exec bool) error {
	data, err := s.Get(digest, exec)
	if err != nil {
		return err
	}
	actual := DigestBytes(data)
	if actual != digest {
		return fmt.Errorf("%w: expected %s, got %s", ErrIntegrityMismatch, digest, actual)
	}
	return nil
}

// HydrateHardlink materializes a cached artifact at dstPath using a zero-copy hardlink.
// If hardlinking fails (for example across filesystem boundaries), it falls back to copying.
func (s *Store) HydrateHardlink(digest string, exec bool, dstPath string) error {
	srcPath, err := s.ObjectPath(digest, exec)
	if err != nil {
		return err
	}
	if _, err := os.Stat(srcPath); err != nil {
		return fmt.Errorf("casv11: missing object %s: %w", digest, err)
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return fmt.Errorf("casv11: mkdir destination: %w", err)
	}
	if err := os.Remove(dstPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("casv11: remove existing destination: %w", err)
	}

	if err := os.Link(srcPath, dstPath); err == nil {
		return nil
	}

	// Cross-device fallback: copy contents.
	in, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("casv11: open fallback source: %w", err)
	}
	defer in.Close()

	mode := os.FileMode(0o644)
	if exec {
		mode = 0o755
	}
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("casv11: create fallback destination: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("casv11: copy fallback: %w", err)
	}
	return out.Close()
}
