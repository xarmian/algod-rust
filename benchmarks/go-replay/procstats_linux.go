// Copyright (c) 2026 Algod DAO
// SPDX-License-Identifier: MIT
// See the LICENSE-MIT file in the repository root for the full license text.

//go:build linux

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// procStats is this process's resource use so far. The Rust replay reads the
// same sources (bin/algod-rust/src/commands/bench_replay.rs).
type procStats struct {
	peakRSS    uint64  // VmHWM from /proc/self/status, bytes
	userS      float64 // getrusage(RUSAGE_SELF) ru_utime
	sysS       float64 // getrusage(RUSAGE_SELF) ru_stime
	writeBytes uint64  // /proc/self/io write_bytes (bytes sent to the block layer)
	ioOK       bool    // /proc/self/io exists (CONFIG_TASK_IO_ACCOUNTING)
}

// procField reads "<key> <value> [kB]" from a /proc file, in bytes.
func procField(path, key string) (uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, key) {
			continue
		}
		fields := strings.Fields(line[len(key):])
		if len(fields) == 0 {
			return 0, false
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, false
		}
		if len(fields) > 1 && fields[1] == "kB" {
			v *= 1024
		}
		return v, true
	}
	return 0, false
}

func readProcStats() procStats {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	hwm, _ := procField("/proc/self/status", "VmHWM:")
	wb, ok := procField("/proc/self/io", "write_bytes:")
	return procStats{
		peakRSS:    hwm,
		userS:      float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6,
		sysS:       float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6,
		writeBytes: wb,
		ioOK:       ok,
	}
}
