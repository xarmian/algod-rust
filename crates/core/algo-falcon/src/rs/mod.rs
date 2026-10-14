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

//! The pure-Rust deterministic Falcon-1024 implementation, ported module by
//! module from the vendored C (`falcon-c/`), keeping the C function names and
//! structure so the two can be read side by side.
//!
//! DIVERGENCE DIV-001: this module tree replaces the cgo-linked C library
//! go-algorand uses (`docs/DIVERGENCES.md`, Phase 21 epic #1926). Every
//! module carries a differential test against the C it ports (feature
//! `c-backend`), and the whole stack is proven byte-identical by
//! `tests/falcon_vectors.rs`.
//!
//! | C file            | Rust module  | lands in |
//! |-------------------|--------------|----------|
//! | `shake.c`         | `shake256`   | #1930    |
//! | `codec.c`         | `codec`      | #1931    |
//! | `fpr.h` / `fpr.c` | `fpr`        | #1932    |
//! | `fft.c`           | `fft`        | #1933    |
//! | `vrfy.c`          | `vrfy`       | #1934    |
//! | `common.c`        | `common`     | #1934    |
//! | `falcon.c`        | `falcon`     | #1935+   |
//! | `deterministic.c` | `det1024`    | #1935+   |
//! | `rng.c`           | `rng`        | #1936    |
//! | `sign.c`          | `sign`       | #1936    |
//! | `keygen.c`        | `keygen`     | #1937    |
//!
//! Arithmetic discipline: wherever the C relies on unsigned wraparound or on
//! truncating casts, the Rust spells it out with `wrapping_*` / explicit
//! `as` casts; everything else is plain arithmetic that the debug-profile
//! tests (overflow checks on) and the differential tests keep honest.

// Modules are wired into `backend::rust` as the port reaches each milestone
// (#1935 verify, #1936 sign, #1937 keygen); until then they are test-only.
#![allow(dead_code)]

pub(crate) mod codec;
pub(crate) mod shake256;
