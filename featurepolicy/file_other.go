// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package featurepolicy

import "os"

// Unsupported file ownership platforms fail closed; configuration remains off.
func rootOwned(os.FileInfo) bool { return false }
