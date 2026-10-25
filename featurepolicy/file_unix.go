// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package featurepolicy

import (
	"os"
	"syscall"
)

func rootOwned(s os.FileInfo) bool { st, ok := s.Sys().(*syscall.Stat_t); return ok && st.Uid == 0 }
