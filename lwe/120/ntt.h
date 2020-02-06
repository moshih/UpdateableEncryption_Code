#include <stdio.h>
#include <stdint.h>

#ifndef CONSTS
#define CONSTS
#include "consts.h"
#endif

int128_t reduce_modq(int128_t input);
int128_t fqmul(int128_t a, int128_t b);
void basemul(int128_t r[2], const int128_t a[2], const int128_t b[2], int128_t zeta);

void poly_basemul(poly_120 *r, const poly_120 *a, const poly_120 *b, const int128_t*zetas);
void poly_frommont_one(poly_120 *r);
void poly_reduce(poly_120 *r);
void ntt(int128_t r[NEWHOPE_N], int128_t* zetas);
void invntt(int128_t r[NEWHOPE_N], int128_t* zetas_inv) ;

void poly_ntt(poly_120 *r, int128_t* zetas);
void poly_invntt(poly_120 *r, int128_t* zetas_inv);