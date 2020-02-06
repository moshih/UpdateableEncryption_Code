#include "ntt.h"

extern int64_t zetas_lower[2048];
extern int64_t zetas_higher[2048];
extern int64_t zetas_inv_lower[2048];
extern int64_t zetas_inv_higher[2048];

int128_t reduce_modq(int128_t input)
{

    uint128_t sign = (uint128_t) input >> 127;
    input += (Q) *sign;

    sign = (uint128_t) input >> 127;

    int128_t output = (input & BLOCK_120) + mulitply_mod((input >> 120), MODP);
    uint128_t diff = (uint128_t) BLOCK_120 - (uint128_t)(output + MODP);

    int128_t delta = mulitply_mod((diff >> 127), Q);
    output -= delta;

    return output;
}

int128_t fqmul(int128_t a, int128_t b)
{
    int128_t product = reduce_modq(mulitply_mod(a, b));
    return reduce_modq(mulitply_mod(qinv, product));
}

void basemul(int128_t r[2], const int128_t a[2], const int128_t b[2], int128_t zeta)
{
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);

    r[1] = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}

void poly_basemul(poly_120 *r, const poly_120 *a, const poly_120 *b, const int128_t *zetas)
{
    unsigned int i;

    for (i = 0; i < NEWHOPE_N / 4; ++i)
    {
        basemul(r->coeffs + 4 *i, a->coeffs + 4 *i, b->coeffs + 4 *i, zetas[NEWHOPE_N / 4 + i]);
        basemul(r->coeffs + 4 *i + 2, a->coeffs + 4 *i + 2, b->coeffs + 4 *i + 2, -zetas[NEWHOPE_N / 4 + i]);
    }
}

void poly_frommont_one(poly_120 *r)
{
    int i;

    for (i = 0; i < NEWHOPE_N; i++) r->coeffs[i] = reduce_modq(mulitply_mod(qinv, r->coeffs[i]));
}

void poly_reduce(poly_120 *r)
{
    int i;

    for (i = 0; i < NEWHOPE_N; i++)
        r->coeffs[i] = reduce_modq(r->coeffs[i]);
}

void ntt(int128_t r[NEWHOPE_N], int128_t *zetas)
{
    unsigned int len, start, j, k;
    int128_t t, zeta;

    k = 1;
    for (len = NEWHOPE_N / 2; len >= 2; len >>= 1)
    {
        for (start = 0; start < NEWHOPE_N; start = j + len)
        {
            zeta = zetas[k++];
            for (j = start; j < start + len; ++j)
            {
                t = fqmul(zeta, r[j + len]);
                r[j + len] = reduce_modq(r[j] - t);
                r[j] = reduce_modq(r[j] + t);
            }
        }
    }
}

void invntt(int128_t r[NEWHOPE_N], int128_t *zetas_inv)
{
    unsigned int start, len, j, k;
    int128_t t, zeta;

    k = 0;
    for (len = 2; len <= NEWHOPE_N / 2; len <<= 1)
    {
        for (start = 0; start < NEWHOPE_N; start = j + len)
        {
            zeta = zetas_inv[k++];
            for (j = start; j < start + len; ++j)
            {
                t = r[j];

                r[j] = reduce_modq(t + r[j + len]);
                r[j + len] = reduce_modq(t - r[j + len]);
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
    }

    for (j = 0; j < NEWHOPE_N; ++j) r[j] = fqmul(r[j], 335537766432);

}

/*************************************************
 *Name:        poly_ntt
 *
 *Description: Computes negacyclic number-theoretic transform (NTT) of
 *             a polynomial in place;
 *             inputs assumed to be in normal order, output in bitreversed order
 *
 *Arguments:   - poly_120 *r: pointer to in/output polynomial
 **************************************************/
void poly_ntt(poly_120 *r, int128_t *zetas)
{
    ntt(r->coeffs, zetas);
}

/*************************************************
 *Name:        poly_invntt
 *
 *Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
 *             a polynomial in place;
 *             inputs assumed to be in bitreversed order, output in normal order
 *
 *Arguments:   - poly_120 *a: pointer to in/output polynomial
 **************************************************/
void poly_invntt(poly_120 *r, int128_t *zetas_inv)
{
    invntt(r->coeffs, zetas_inv);
}