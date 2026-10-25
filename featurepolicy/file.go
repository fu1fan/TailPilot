// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package featurepolicy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ReadFile accepts only absolute, root-owned 0600 regular files, with no symlink
// components and no non-root-writable parent. Rechecking the opened inode also
// prevents swapping the final component between Lstat and Open. Ancestors are
// root-owned and not writable by non-root, so unprivileged rename is impossible.
func ReadFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("policy path must be canonical and absolute")
	}
	// An absent optional configuration is default-off even on hosts whose
	// system directory is a symlink (for example /etc on Darwin). Existing
	// files still undergo every trust check below.
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, err
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		if !s.IsDir() || s.Mode().Perm()&0022 != 0 || !rootOwned(s) {
			return nil, fmt.Errorf("untrusted policy parent")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	s, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || !rootOwned(s) || s.Size() > MaxConfigBytes {
		return nil, fmt.Errorf("untrusted policy file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !os.SameFile(s, opened) || opened.Mode().Perm() != 0600 || !rootOwned(opened) {
		return nil, fmt.Errorf("policy file changed")
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > MaxConfigBytes {
		return nil, fmt.Errorf("policy file too large")
	}
	return b, nil
}
