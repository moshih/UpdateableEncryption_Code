#include "ntt_268369921.h"

extern int32_t zetas_268369921[NEWHOPE_N / 2];
extern int32_t zetas_inv_268369921[NEWHOPE_N / 2];

extern int32_t zetas_avx_268369921[2304];
extern int32_t zetas_inv_avx_268369921[2304];

/*************************************************
 *Name:        mult_poly_ntru_268369921
 *
 *Description: This should ONLY be used in testing. Runs slowly but is correct.
 *
 *Arguments:   - poly_28 *result: pointer to the product
 *             - poly_28 *poly_a: pointer to the first poly_28 input
 *             - poly_28 *poly_b: pointer to the second poly_28 input
 *
 *Returns:     None
 **************************************************/
void mult_poly_ntru_268369921(poly_28 *result, poly_28 *poly_a, poly_28 *poly_b)
{
    size_t i, j;

    for (i = 0; i < NEWHOPE_N; ++i)
    {
        result->coeffs[i] = 0;
    }
    for (i = 0; i < NEWHOPE_N; ++i)
    {
        for (j = 0; j < NEWHOPE_N; j++)
        {
            size_t deg = (i + j) % NEWHOPE_N;
            int64_t tmp = ((int64_t) poly_a->coeffs[(i)] *poly_b->coeffs[j]) % (int64_t) QA;

            if (((i + j) / NEWHOPE_N) % 2 == 1) tmp = -tmp;

            result->coeffs[deg] = ((int64_t) tmp + (int64_t) result->coeffs[deg]) % (int64_t) QA;
        }
    }
}

/*************************************************
 *Name:        barrett_reduce_268369921
 *
 *Description: Barrett reduction; given a 32-bit integer a, computes
 *             32-bit integer congruent to a mod q in {0,...,q}
 *
 *Arguments:   - int32_t a: input integer to be reduced
 *
 *Returns:     integer in {0,...,q} congruent to a modulo q.
 **************************************************/

int32_t barrett_reduce_268369921(int32_t a)
{
    int64_t t;
    const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) QA + 1;

    t = v * a;
    t >>= BARRETT_REDUCE_FACTOR;
    t *= (int64_t) QA;

    return a - t;
}

/*************************************************
 *Name:        poly_reduce
 *
 *Description: Applies Barrett reduction to all coefficients of a polynomial
 *             for details of the Barrett reduction see comments in reduce.c
 *
 *Arguments:   - poly_28 *r:       pointer to input/output polynomial
 **************************************************/
static void poly_reduce(poly_28 *r)
{
    int i;

    for (i = 0; i < NEWHOPE_N; i++)
        r->coeffs[i] = barrett_reduce_268369921(r->coeffs[i]);
}

/*************************************************
 *Name:        poly_invntt_avx_268369921
 *
 *Description: Applies inverse NTT to all coefficients of a polynomial
 *
 *Arguments:   - poly_28 *r:       pointer to input/output polynomial
 **************************************************/
void poly_invntt_avx_268369921(poly_28 *r)
{
    inv_ntt_avx_268369921(r->coeffs, zetas_inv_avx_268369921);
}

/*************************************************
*Name:        montgomery_reduce_268369921
*
*Description: Montgomery reduction; given a 64-bit integer a, computes
*             32-bit integer congruent to a *R^-1 mod q,
*             where R=2^32
*
*Arguments:   - int64_t a: input integer to be reduced; has to be in {-q2^31,...,q2^31-1}
*
*Returns:     integer in {-q+1,...,q-1} congruent to a *R^-1 modulo q.
**************************************************/
int32_t montgomery_reduce_268369921(int64_t a)
{

    int64_t t;
    int32_t u;

    u = a *(int64_t) QINV_S32_A;

    t = (int64_t) u *(int64_t) QA;
    t = a - t;
    t >>= 32;

    return t;
}

static int32_t fqmul(int32_t a, int32_t b)
{
    return montgomery_reduce_268369921((int64_t) a *b);
}

/*************************************************
 *Name:        basemul
 *
 *Description: Multiplication of polynomials in Zq[X]/((X^2-zeta))
 *             used for multiplication of elements in Rq in NTT domain
 *
 *Arguments:   - int32_t r[2]: pointer to the output polynomial
 *             - const int32_t a[2]: pointer to the first factor
 *             - const int32_t b[2]: pointer to the second factor
 *             - int32_t zeta: integer defining the reduction polynomial
 **************************************************/

static void basemul(int32_t r[2], const int32_t a[2], const int32_t b[2], int32_t zeta)
{
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);

    r[1] = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}

/*************************************************
 *Name:        poly_basemul_268369921
 *
 *Description: Multiplication of two polynomials in NTT domain
 *
 *Arguments:   - poly_28 *r:       pointer to output polynomial
 *             - const poly_28 *a: pointer to first input polynomial
 *             - const poly_28 *b: pointer to second input polynomial
 **************************************************/

void poly_basemul_268369921(poly_28 *r, const poly_28 *a, const poly_28 *b)
{
    unsigned int i;

    for (i = 0; i < NEWHOPE_N / 4; ++i)
    {
        basemul(r->coeffs + 4 *i, a->coeffs + 4 *i, b->coeffs + 4 *i, zetas_268369921[NEWHOPE_N / 4 + i]);
        basemul(r->coeffs + 4 *i + 2, a->coeffs + 4 *i + 2, b->coeffs + 4 *i + 2, -zetas_268369921[NEWHOPE_N / 4 + i]);
    }
}

/*************************************************
 *Name:        poly_frommont_one_268369921
 *
 *Description: Inplace conversion of all coefficients of a polynomial 
 *             from Montgomery domain to normal domain
 *
 *Arguments:   - poly_28 *r:       pointer to input/output polynomial
 **************************************************/

void poly_frommont_one_268369921(poly_28 *r)
{
    int i;

    for (i = 0; i < NEWHOPE_N; i++)
        r->coeffs[i] = montgomery_reduce_268369921((int64_t) r->coeffs[i]);
}

/*************************************************
 *Name:        ntt_268369921
 *
 *Description: Inplace number-theoretic transform (NTT) in Rq
 *             input is in standard order, output is in bitreversed order
 *
 *Arguments:   - int32_t r[NEWHOPE_N]: pointer to input/output vector of elements of Zq
 **************************************************/
void ntt_268369921(int32_t r[NEWHOPE_N])
{
    unsigned int len, start, j, k;
    int32_t t, zeta;

    k = 1;

    for (len = NEWHOPE_N / 2; len >= 2; len >>= 1)
    {
        for (start = 0; start < NEWHOPE_N; start = j + len)
        {
            zeta = zetas_268369921[k++];
            for (j = start; j < start + len; ++j)
            {
                t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
        
    }
}

/*************************************************
 *Name:        invntt_268369921
 *
 *Description: Inplace inverse number-theoretic transform in Rq
 *             input is in bitreversed order, output is in standard order
 *
 *Arguments:   - int32_t r[NEWHOPE_N]: pointer to input/output vector of elements of Zq
 **************************************************/
void invntt_268369921(int32_t r[NEWHOPE_N])
{
    unsigned int start, len, j, k;
    int32_t t, zeta;

    k = 0;
    for (len = 2; len <= NEWHOPE_N / 2; len <<= 1)
    {
        for (start = 0; start < NEWHOPE_N; start = j + len)
        {
            zeta = zetas_inv_268369921[k++];
            for (j = start; j < start + len; ++j)
            {
                t = r[j];

                r[j] = barrett_reduce_268369921(t + r[j + len]);
                r[j + len] = t - r[j + len];
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
    }
    
    for (j = 0; j < NEWHOPE_N; ++j)
        r[j] = fqmul(r[j], zetas_inv_268369921[NEWHOPE_N / 2 - 1]);
}

/*************************************************
 *Name:        poly_ntt_268369921
 *
 *Description: Computes negacyclic number-theoretic transform (NTT) of
 *             a polynomial in place;
 *             inputs assumed to be in normal order, output in bitreversed order
 *
 *Arguments:   - poly_28 *r: pointer to in/output polynomial
 **************************************************/
void poly_ntt_268369921(poly_28 *r)
{
    ntt_268369921(r->coeffs);
    poly_reduce(r);
}

/*************************************************
 *Name:        poly_invntt_268369921
 *
 *Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
 *             a polynomial in place;
 *             inputs assumed to be in bitreversed order, output in normal order
 *
 *Arguments:   - poly_28 *a: pointer to in/output polynomial
 **************************************************/
void poly_invntt_268369921(poly_28 *r)
{
    invntt_268369921(r->coeffs);
}