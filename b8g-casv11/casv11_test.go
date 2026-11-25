package casv11

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestB8GAbiMagicV3(t *testing.T) {
	if B8GAbiMagicV3 != uint32(0x33564742) {
		t.Fatalf("unexpected B8GAbiMagicV3: got 0x%x, want 0x33564742", B8GAbiMagicV3)
	}
}

func TestPutGetAndLayout(t *testing.T) {
	root := t.TempDir()
	store := NewStore(root)

	payload := []byte("go-build-artifact-object-bytes")
	digest, objPath, err := store.Put(payload, false)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	wantSuffix := filepath.Join("v11", "files", digest[:2], digest)
	if !strings.HasSuffix(objPath, wantSuffix) {
		t.Fatalf("unexpected non-exec object path %q, want suffix %q", objPath, wantSuffix)
	}

	if !store.Has(digest, false) {
		t.Fatalf("expected store.Has(%s, false) to be true", digest)
	}

	got, err := store.Get(digest, false)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get returned %q, want %q", got, payload)
	}

	if err := store.Verify(digest, false); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Idempotent second Put returns same digest and path.
	digest2, objPath2, err := store.Put(payload, false)
	if err != nil {
		t.Fatalf("second Put failed: %v", err)
	}
	if digest2 != digest || objPath2 != objPath {
		t.Fatalf("idempotent Put mismatch: got (%s, %s), want (%s, %s)", digest2, objPath2, digest, objPath)
	}
}

func TestPutExecAndHydrateHardlink(t *testing.T) {
	root := t.TempDir()
	store := NewStore(root)

	binPayload := []byte("#!/bin/sh\necho awesome-os-go-artifact\n")
	digest, objPath, err := store.Put(binPayload, true)
	if err != nil {
		t.Fatalf("Put(exec=true) failed: %v", err)
	}

	wantSuffix := filepath.Join("v11", "files", digest[:2], digest+"-exec")
	if !strings.HasSuffix(objPath, wantSuffix) {
		t.Fatalf("unexpected exec object path %q, want suffix %q", objPath, wantSuffix)
	}

	dst := filepath.Join(t.TempDir(), "nested", "bin", "tool")
	if err := store.HydrateHardlink(digest, true, dst); err != nil {
		t.Fatalf("HydrateHardlink failed: %v", err)
	}

	hydrated, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed: %v", dst, err)
	}
	if !bytes.Equal(hydrated, binPayload) {
		t.Fatalf("hydrated content mismatch: got %q, want %q", hydrated, binPayload)
	}

	srcInfo, err := os.Stat(objPath)
	if err != nil {
		t.Fatalf("Stat(%s) failed: %v", objPath, err)
	}
	dstInfo, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("Stat(%s) failed: %v", dst, err)
	}
	if !os.SameFile(srcInfo, dstInfo) {
		t.Fatalf("expected HydrateHardlink to create a hardlink (os.SameFile == true)")
	}
}

func TestValidateDigestRejectsTraversal(t *testing.T) {
	store := NewStore(t.TempDir())
	if _, err := store.ObjectPath("../escape", false); !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("expected ErrInvalidDigest for traversal input, got %v", err)
	}
	if _, err := store.ObjectPath(strings.Repeat("G", 128), false); !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("expected ErrInvalidDigest for non-hex input, got %v", err)
	}
}

func TestPutFileAndVerifyDetectsCorruption(t *testing.T) {
	root := t.TempDir()
	store := NewStore(root)

	src := filepath.Join(t.TempDir(), "pkg.a")
	if err := os.WriteFile(src, []byte("archive-data-v11"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	digest, objPath, err := store.PutFile(src, false)
	if err != nil {
		t.Fatalf("PutFile failed: %v", err)
	}
	if err := store.Verify(digest, false); err != nil {
		t.Fatalf("Verify failed on clean object: %v", err)
	}

	if err := os.WriteFile(objPath, []byte("corrupted"), 0o644); err != nil {
		t.Fatalf("corrupt write failed: %v", err)
	}
	if err := store.Verify(digest, false); !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch, got %v", err)
	}
}
