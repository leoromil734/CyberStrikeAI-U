package app

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cyberstrike-ai/internal/evidence"
)

// Each path component is checked before an exclusive file create. Registry
// rechecks confinement and links before any file is ingested or returned.
func makeManagedDirectory(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return evidence.ErrUnsafePath
	}
	parent := filepath.Dir(path)
	if parent != path {
		if err := makeManagedDirectory(parent); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err = os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return evidence.ErrUnsafePath
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.EqualFold(filepath.Clean(resolved), path) {
		return evidence.ErrUnsafePath
	}
	return nil
}

func writeManagedOriginal(dir, name string, data []byte) error {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "\\/:\x00") || name == "." || name == ".." {
		return evidence.ErrUnsafePath
	}
	if err := makeManagedDirectory(dir); err != nil {
		return err
	}
	expected, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	pinned, err := root.Stat(".")
	if err != nil || !os.SameFile(expected, pinned) || makeManagedDirectory(dir) != nil {
		return evidence.ErrUnsafePath
	}
	if _, statErr := root.Lstat(name); statErr == nil {
		return verifyManagedOriginal(root, name, data)
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return verifyManagedOriginal(root, name, data)
	}
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		// Only remove the file created by this call, never an existing original.
		_ = root.Remove(name)
		return errors.Join(writeErr, closeErr)
	}
	return nil
}

func verifyManagedOriginal(root *os.Root, name string, data []byte) error {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return evidence.ErrUnsafePath
	}
	if before.Size() != int64(len(data)) {
		return evidence.ErrChanged
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return evidence.ErrUnsafePath
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, int64(len(data))+1))
	if err != nil {
		return err
	}
	after, err := root.Lstat(name)
	if err != nil || !after.Mode().IsRegular() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
		return evidence.ErrUnsafePath
	}
	want := sha256.Sum256(data)
	if n != int64(len(data)) || after.Size() != n || !after.ModTime().Equal(before.ModTime()) || !bytes.Equal(h.Sum(nil), want[:]) {
		return evidence.ErrChanged
	}
	return nil
}
