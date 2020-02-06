#include <stdio.h>
#include <stdint.h>

#ifndef CONSTS
#define CONSTS
#include "consts.h"
#endif

#if (MODULO == 268409857)
#include "ntt_avx.h"

int32_t montgomery_reduce(int64_t a);
int32_t fqmul(int32_t a, int32_t b);
int32_t barrett_reduce(int32_t a);
void basemul(int32_t r[2], const int32_t a[2], const int32_t b[2], int32_t zeta);

void poly_basemul(poly_28 *r, const poly_28 *a, const poly_28 *b);
void poly_frommont_one(poly_28 *r);
void poly_reduce(poly_28 *r);

void poly_ntt_avx(poly_28 *r);
void poly_invntt_avx(poly_28 *r);

void ntt(int32_t r[NEWHOPE_N]);
void invntt(int32_t r[NEWHOPE_N]);

void poly_ntt(poly_28 *r);
void poly_invntt(poly_28 *r);

#endif