/*
 * Copyright (C) 2026 Algod DAO
 * This file is part of algod-rust (https://github.com/xarmian/algod-rust).
 *
 * algod-rust is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * algod-rust is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Test-only shim (cargo feature `c-internals-test`, Phase 21 / DIV-001):
 * re-exports the `static inline` floating-point helpers of the vendored
 * `falcon-c/fpr.h` (Falcon Project, MIT) under the `falcon_shim_x_` prefix so
 * the pure-Rust port's differential tests can compare against them bit for
 * bit. Never linked into a release build.
 */
#include <stdint.h>
#include "inner.h"

int64_t falcon_shim_x_fpr_rint(uint64_t x) { return fpr_rint(x); }
int64_t falcon_shim_x_fpr_floor(uint64_t x) { return fpr_floor(x); }
int64_t falcon_shim_x_fpr_trunc(uint64_t x) { return fpr_trunc(x); }
int falcon_shim_x_fpr_lt(uint64_t x, uint64_t y) { return fpr_lt(x, y); }
uint64_t falcon_shim_x_fpr_of(int64_t i) { return fpr_of(i); }
uint64_t falcon_shim_x_fpr_neg(uint64_t x) { return fpr_neg(x); }
uint64_t falcon_shim_x_fpr_half(uint64_t x) { return fpr_half(x); }
uint64_t falcon_shim_x_fpr_double(uint64_t x) { return fpr_double(x); }
uint64_t falcon_shim_x_fpr_sub(uint64_t x, uint64_t y) { return fpr_sub(x, y); }
uint64_t falcon_shim_x_fpr_sqr(uint64_t x) { return fpr_sqr(x); }
uint64_t falcon_shim_x_fpr_inv(uint64_t x) { return fpr_inv(x); }
