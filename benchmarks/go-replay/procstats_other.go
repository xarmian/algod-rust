// Copyright (c) 2026 Algod DAO
// SPDX-License-Identifier: MIT
// See the LICENSE-MIT file in the repository root for the full license text.

//go:build !linux

package main

// procStats: resource metrics come from /proc and getrusage, so they are
// only measured on Linux (the platform the replay tier runs on). Elsewhere
// they read as zero.
type procStats struct {
	peakRSS    uint64
	userS      float64
	sysS       float64
	writeBytes uint64
	ioOK       bool
}

func readProcStats() procStats { return procStats{} }
