#include <stdio.h>
#include <stdint.h>

#ifndef CONSTS
#define CONSTS
#include "consts.h"
#endif

int64_t montgomery_reduce(__int128 a);
int64_t fqmul(int64_t a, int64_t b);
int64_t barrett_reduce(int64_t a);
void basemul(int64_t r[2], const int64_t a[2], const int64_t b[2], int64_t zeta);

void poly_basemul(poly_60 *r, const poly_60 *a, const poly_60 *b);
void poly_frommont_one(poly_60 *r);
void poly_reduce(poly_60 *r);

void ntt(int64_t r[NEWHOPE_N]);
void invntt(int64_t r[NEWHOPE_N]);

void poly_ntt(poly_60 *r);
void poly_invntt(poly_60 *r);