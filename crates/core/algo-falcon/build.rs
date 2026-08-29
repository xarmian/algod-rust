// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Build script for compiling the vendored Falcon C library.
//
// The C sources come from github.com/algorand/falcon v0.1.0, which is
// Algorand's deterministic Falcon-1024 implementation (MIT licensed).
//
// Key build settings (matching the upstream config.h):
//   - FALCON_FPEMU=1    — emulated floating-point for deterministic signing
//   - FALCON_FPNATIVE=0 — disable native FP (defence-in-depth)
//   - FALCON_AVX2=0     — disable AVX2 (defence-in-depth)
//   - FALCON_FMA=0      — disable FMA (known non-determinism risk)

fn main() {
    let falcon_dir = "falcon-c";

    let c_files = [
        "codec.c",
        "common.c",
        "deterministic.c",
        "falcon.c",
        "fft.c",
        "fpr.c",
        "keygen.c",
        "rng.c",
        "shake.c",
        "sign.c",
        "vrfy.c",
    ];

    let mut build = cc::Build::new();
    build
        .include(falcon_dir)
        // Optimisation — the FP emulation tables (fpr.c) are large and
        // benefit from -O3, matching the upstream Makefile.
        .opt_level(3)
        // Warnings matching the Go cgo flags (minus pedantic/strict-proto
        // which fire on some compilers and aren't safety-critical here).
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wshadow")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-overlength-strings")
        .flag_if_supported("-Wno-strict-prototypes")
        // Disable warnings that fire on this specific codebase with clang
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-unused-function");

    for file in &c_files {
        build.file(format!("{}/{}", falcon_dir, file));
    }

    build.compile("falcon");

    // Rerun if any source file changes.
    println!("cargo:rerun-if-changed={}", falcon_dir);
    for file in &c_files {
        println!("cargo:rerun-if-changed={}/{}", falcon_dir, file);
    }
    for header in &[
        "config.h",
        "falcon.h",
        "deterministic.h",
        "inner.h",
        "fpr.h",
    ] {
        println!("cargo:rerun-if-changed={}/{}", falcon_dir, header);
    }
}
