#include <stdio.h>
#include <stdint.h>

#ifndef CONSTS
#define CONSTS
#include "consts.h"
#endif

uint128_t fqmul(uint128_t a, uint128_t b);
void basemul(uint128_t r[2], const uint128_t a[2], const uint128_t b[2], uint128_t zeta);
void poly_basemul(poly_128 *r, const poly_128 *a, const poly_128 *b, const uint128_t*zetas);
void poly_frommont_one(poly_128 *r);
void ntt(uint128_t r[NEWHOPE_N], uint128_t* zetas);
void invntt(uint128_t r[NEWHOPE_N], uint128_t* zetas_inv);
void poly_ntt(poly_128 *r, uint128_t* zetas);
void poly_invntt(poly_128 *r, uint128_t* zetas_inv);