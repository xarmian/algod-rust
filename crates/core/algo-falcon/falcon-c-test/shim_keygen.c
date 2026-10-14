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
 * compiles the vendored `falcon-c/keygen.c` (Falcon Project, MIT) a second
 * time under a private symbol prefix so its `static` steps can be called
 * from the differential tests. Every symbol keygen.c needs from the rest
 * of the library is redirected to the real (`falcon_inner_`) one.
 */
#include <stdint.h>
#define FALCON_PREFIX falcon_shimk
#define falcon_shimk_FFT falcon_inner_FFT
#define falcon_shimk_iFFT falcon_inner_iFFT
#define falcon_shimk_poly_add falcon_inner_poly_add
#define falcon_shimk_poly_sub falcon_inner_poly_sub
#define falcon_shimk_poly_neg falcon_inner_poly_neg
#define falcon_shimk_poly_adj_fft falcon_inner_poly_adj_fft
#define falcon_shimk_poly_mul_fft falcon_inner_poly_mul_fft
#define falcon_shimk_poly_muladj_fft falcon_inner_poly_muladj_fft
#define falcon_shimk_poly_mulselfadj_fft falcon_inner_poly_mulselfadj_fft
#define falcon_shimk_poly_mulconst falcon_inner_poly_mulconst
#define falcon_shimk_poly_div_fft falcon_inner_poly_div_fft
#define falcon_shimk_poly_invnorm2_fft falcon_inner_poly_invnorm2_fft
#define falcon_shimk_poly_add_muladj_fft falcon_inner_poly_add_muladj_fft
#define falcon_shimk_poly_mul_autoadj_fft falcon_inner_poly_mul_autoadj_fft
#define falcon_shimk_poly_div_autoadj_fft falcon_inner_poly_div_autoadj_fft
#define falcon_shimk_poly_LDL_fft falcon_inner_poly_LDL_fft
#define falcon_shimk_poly_LDLmv_fft falcon_inner_poly_LDLmv_fft
#define falcon_shimk_poly_split_fft falcon_inner_poly_split_fft
#define falcon_shimk_poly_merge_fft falcon_inner_poly_merge_fft
#define falcon_shimk_compute_public falcon_inner_compute_public
#define falcon_shimk_prng_init falcon_inner_prng_init
#define falcon_shimk_prng_refill falcon_inner_prng_refill
#define falcon_shimk_prng_get_bytes falcon_inner_prng_get_bytes
#define falcon_shimk_i_shake256_init falcon_inner_i_shake256_init
#define falcon_shimk_i_shake256_inject falcon_inner_i_shake256_inject
#define falcon_shimk_i_shake256_flip falcon_inner_i_shake256_flip
#define falcon_shimk_i_shake256_extract falcon_inner_i_shake256_extract
#define falcon_shimk_max_fg_bits falcon_inner_max_fg_bits
#define falcon_shimk_max_FG_bits falcon_inner_max_FG_bits
#define falcon_shimk_max_sig_bits falcon_inner_max_sig_bits
#define falcon_shimk_fpr_add falcon_inner_fpr_add
#define falcon_shimk_fpr_mul falcon_inner_fpr_mul
#define falcon_shimk_fpr_div falcon_inner_fpr_div
#define falcon_shimk_fpr_sqrt falcon_inner_fpr_sqrt
#define falcon_shimk_fpr_scaled falcon_inner_fpr_scaled
#define falcon_shimk_fpr_expm_p63 falcon_inner_fpr_expm_p63
#define falcon_shimk_fpr_gm_tab falcon_inner_fpr_gm_tab
#define falcon_shimk_fpr_p2_tab falcon_inner_fpr_p2_tab
#define falcon_shimk_mq_NTT falcon_inner_mq_NTT
#define falcon_shimk_mq_iNTT falcon_inner_mq_iNTT
#define falcon_shimk_is_short falcon_inner_is_short

#include "inner.h"
#include "../falcon-c/keygen.c"

/* FALCON_KG_CHACHA20 is off in the vendored config.h: RNG_CONTEXT is the
 * SHAKE256 context itself. */
int falcon_shim_x_mkgauss(inner_shake256_context *rng, unsigned logn) { return mkgauss(rng, logn); }
void falcon_shim_x_poly_small_mkgauss(inner_shake256_context *rng, int8_t *f, unsigned logn)
{
	poly_small_mkgauss(rng, f, logn);
}
uint32_t falcon_shim_x_poly_small_sqnorm(const int8_t *f, unsigned logn) { return poly_small_sqnorm(f, logn); }
int falcon_shim_x_solve_NTRU(unsigned logn, int8_t *F, int8_t *G,
	const int8_t *f, const int8_t *g, int lim, uint32_t *tmp)
{
	return solve_NTRU(logn, F, G, f, g, lim, tmp);
}
int falcon_shim_x_solve_NTRU_deepest(unsigned logn_top, const int8_t *f, const int8_t *g, uint32_t *tmp)
{
	return solve_NTRU_deepest(logn_top, f, g, tmp);
}
int falcon_shim_x_solve_NTRU_intermediate(unsigned logn_top, const int8_t *f, const int8_t *g,
	unsigned depth, uint32_t *tmp)
{
	return solve_NTRU_intermediate(logn_top, f, g, depth, tmp);
}
int falcon_shim_x_solve_NTRU_binary_depth1(unsigned logn_top, const int8_t *f, const int8_t *g, uint32_t *tmp)
{
	return solve_NTRU_binary_depth1(logn_top, f, g, tmp);
}
int falcon_shim_x_solve_NTRU_binary_depth0(unsigned logn, const int8_t *f, const int8_t *g, uint32_t *tmp)
{
	return solve_NTRU_binary_depth0(logn, f, g, tmp);
}
