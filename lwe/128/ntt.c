#include "ntt.h"

extern uint64_t zetas_lower[2048];
extern uint64_t zetas_higher[2048];
extern uint64_t zetas_inv_lower[2048];
extern uint64_t zetas_inv_higher[2048];

uint128_t fqmul(uint128_t a, uint128_t b)
{
    return mulitply_mod(qinv, mulitply_mod(a, b));
}

void basemul(uint128_t r[2], const uint128_t a[2], const uint128_t b[2], uint128_t zeta)
{
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] = addModP(r[0], fqmul(a[0], b[0]));

    r[1] = addModP(fqmul(a[0], b[1]), fqmul(a[1], b[0]));
}

void poly_basemul(poly_128 *r, const poly_128 *a, const poly_128 *b, const uint128_t *zetas)
{
    unsigned int i;

    for (i = 0; i < NEWHOPE_N / 4; ++i)
    {
        basemul(r->coeffs + 4 *i, a->coeffs + 4 *i, b->coeffs + 4 *i, zetas[NEWHOPE_N / 4 + i]);
        basemul(r->coeffs + 4 *i + 2, a->coeffs + 4 *i + 2, b->coeffs + 4 *i + 2, subModP(0, zetas[NEWHOPE_N / 4 + i]));
    }
}

void poly_frommont_one(poly_128 *r)
{
    int i;

    for (i = 0; i < NEWHOPE_N; i++)
        r->coeffs[i] = mulitply_mod(qinv, r->coeffs[i]);
}

void ntt(uint128_t r[NEWHOPE_N], uint128_t *zetas)
{
    unsigned int len, start, j, k;
    uint128_t t, zeta;

    k = 1;
    for (len = NEWHOPE_N / 2; len >= 2; len >>= 1)
    {
        for (start = 0; start < NEWHOPE_N; start = j + len)
        {
            zeta = zetas[k++];
            for (j = start; j < start + len; ++j)
            {
                t = fqmul(zeta, r[j + len]);
                r[j + len] = subModP(r[j], t);
                r[j] = addModP(r[j], t);
            }
        }
    }
}

void invntt(uint128_t r[NEWHOPE_N], uint128_t *zetas_inv)
{
    unsigned int start, len, j, k;
    uint128_t t, zeta;

    k = 0;
    for (len = 2; len <= NEWHOPE_N / 2; len <<= 1)
    {
        for (start = 0; start < NEWHOPE_N; start = j + len)
        {
            zeta = zetas_inv[k++];
            for (j = start; j < start + len; ++j)
            {
                t = r[j];

                r[j] = addModP(t, r[j + len]);
                r[j + len] = subModP(t, r[j + len]);
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
    }

    for (j = 0; j < NEWHOPE_N; ++j) r[j] = fqmul(r[j], zetas_inv[NEWHOPE_N / 2 - 1]);

}

/*************************************************
 *Name:        poly_ntt
 *
 *Description: Computes negacyclic number-theoretic transform (NTT) of
 *             a polynomial in place;
 *             inputs assumed to be in normal order, output in bitreversed order
 *
 *Arguments:   - poly_128 *r: pointer to in/output polynomial
 **************************************************/
void poly_ntt(poly_128 *r, uint128_t *zetas)
{
    ntt(r->coeffs, zetas);
    //poly_reduce(r);
}

/*************************************************
 *Name:        poly_invntt
 *
 *Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
 *             a polynomial in place;
 *             inputs assumed to be in bitreversed order, output in normal order
 *
 *Arguments:   - poly_128 *a: pointer to in/output polynomial
 **************************************************/
void poly_invntt(poly_128 *r, uint128_t *zetas_inv)
{
    invntt(r->coeffs, zetas_inv);
}