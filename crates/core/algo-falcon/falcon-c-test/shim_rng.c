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
 * re-exports the `static inline` PRNG getters of the vendored
 * `falcon-c/inner.h` (Falcon Project, MIT) for the differential tests.
 */
#include <stdint.h>
#include "inner.h"

uint64_t falcon_shim_x_prng_get_u64(prng *p) { return prng_get_u64(p); }
unsigned falcon_shim_x_prng_get_u8(prng *p) { return prng_get_u8(p); }
