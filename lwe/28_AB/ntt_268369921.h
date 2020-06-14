#include <stdio.h>
#include <stdint.h>

#ifndef CONSTS
#define CONSTS
#include "consts.h"
#endif

#include "ntt_avx.h"

int32_t montgomery_reduce_268369921(int64_t a);
static int32_t fqmul(int32_t a, int32_t b);
int32_t barrett_reduce_268369921(int32_t a);
static void basemul(int32_t r[2], const int32_t a[2], const int32_t b[2], int32_t zeta);

void poly_basemul_268369921(poly_28 *r, const poly_28 *a, const poly_28 *b);
void poly_frommont_one_268369921(poly_28 *r);
static void poly_reduce_268369921(poly_28 *r);

void poly_invntt_avx_268369921(poly_28 *r);

void ntt_268369921(int32_t r[NEWHOPE_N]);
void invntt_268369921(int32_t r[NEWHOPE_N]);

void poly_ntt_268369921(poly_28 *r);
void poly_invntt_268369921(poly_28 *r);

void mult_poly_ntru_268369921(poly_28 *result, poly_28 *poly_a, poly_28 *poly_b);