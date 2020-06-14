#include "crypto_algorithms.h"

/*************************************************
 *Name:        poly_uniform_ref_poly_28_AB
 *
 *Description: Takes in a 32 bytes seed, generates 2 poly_28 with shake128 
 *             uniformly random elements in mod QA for the first, mod QB for the second.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_28 *a: pointer to the poly_28 to be generated mod QA
 *             - poly_28 *b: pointer to the poly_28 to be generated mod QB
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_poly_28_AB(poly_28 *a, poly_28 *b, const unsigned char *seed)
{
    unsigned int ctr = 0;
    uint32_t val;
    uint64_t state[25];
    uint8_t buf[SHAKE128_RATE];
    uint8_t extseed[(NEWHOPE_SYMBYTES + 2)];
    int i, j;
    uint32_t sample_1, sample_2;

    for (i = 0; i < NEWHOPE_SYMBYTES + 2; i++) extseed[i] = 0;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        extseed[i] = seed[i];

    int coeffs_written = 0;
    int iteration = 0;
    uint8_t *a_byte = (int8_t*) a;

    while (coeffs_written != NEWHOPE_N)
    {
        if (iteration == 65536) printf("ERROR: poly_uniform_ref_poly_28: iteration hit its limit\n");

        extseed[NEWHOPE_SYMBYTES] = iteration; /*domain-separate the 16 independent calls */

        if (extseed[NEWHOPE_SYMBYTES] == 0) extseed[NEWHOPE_SYMBYTES + 1]++;

        shake128_absorb(state, extseed, NEWHOPE_SYMBYTES + 2);
        shake128_squeezeblocks(buf, 1, state);

        for (j = 0; j < SHAKE128_RATE - SAMPLE_BLOCK_SIZE && coeffs_written < NEWHOPE_N; j += 7)
        {
            sample_1 = ((uint32_t) buf[j] | ((uint32_t) buf[j + 1] << 8) | ((uint32_t) buf[j + 2] << 16) | ((uint32_t)(buf[j + 3] &15) << 24));

            if (sample_1 < QA)
            {
                a->coeffs[coeffs_written] = sample_1;
                coeffs_written++;
            }

            if (coeffs_written == NEWHOPE_N) break;

            sample_2 = ((uint32_t) buf[j + 4] | ((uint32_t) buf[j + 5] << 8) | ((uint32_t) buf[j + 6] << 16) | ((uint32_t)(buf[j + 3] &240) << 20));
            if (sample_2 < QA)
            {
                a->coeffs[coeffs_written] = sample_2;
                coeffs_written++;
            }
        }

        iteration++;
    }

    coeffs_written = 0;
    while (coeffs_written != NEWHOPE_N)
    {
        if (iteration == 65536) printf("ERROR: poly_uniform_ref_poly_28: iteration hit its limit\n");

        extseed[NEWHOPE_SYMBYTES] = iteration; /*domain-separate the 16 independent calls */

        if (extseed[NEWHOPE_SYMBYTES] == 0) extseed[NEWHOPE_SYMBYTES + 1]++;

        shake128_absorb(state, extseed, NEWHOPE_SYMBYTES + 2);
        shake128_squeezeblocks(buf, 1, state);

        for (j = 0; j < SHAKE128_RATE - SAMPLE_BLOCK_SIZE && coeffs_written < NEWHOPE_N; j += 7)
        {
            sample_1 = ((uint32_t) buf[j] | ((uint32_t) buf[j + 1] << 8) | ((uint32_t) buf[j + 2] << 16) | ((uint32_t)(buf[j + 3] &15) << 24));

            if (sample_1 < QB)
            {
                b->coeffs[coeffs_written] = sample_1;
                coeffs_written++;
            }

            if (coeffs_written == NEWHOPE_N) break;

            sample_2 = ((uint32_t) buf[j + 4] | ((uint32_t) buf[j + 5] << 8) | ((uint32_t) buf[j + 6] << 16) | ((uint32_t)(buf[j + 3] &240) << 20));
            if (sample_2 < QB)
            {
                b->coeffs[coeffs_written] = sample_2;
                coeffs_written++;
            }
        }

        iteration++;
    }
}

/*************************************************
 *Name:        poly_uniform_ref_poly_28_avx
 *
 *Description: AVX2 form of poly_uniform_ref_poly_28.
 *             Takes in a 32 bytes seed, generates 2 poly_28 with shake128 
 *             uniformly random elements in mod QA for the first, mod QB for the second.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_28 *a: pointer to the poly_28 to be generated mod QA
 *             - poly_28 *b: pointer to the poly_28 to be generated mod QB
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_poly_28_AB_avx(poly_28 *a, poly_28 *b, const unsigned char *seed)
{
    uint8_t buf[4 *SHAKE128_RATE];
    uint8_t extseed0[NEWHOPE_SYMBYTES + 2];
    uint8_t extseed1[NEWHOPE_SYMBYTES + 2];
    uint8_t extseed2[NEWHOPE_SYMBYTES + 2];
    uint8_t extseed3[NEWHOPE_SYMBYTES + 2];
    int i, j;
    uint32_t sample_1, sample_2;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        extseed0[i] = seed[i];
        extseed1[i] = seed[i];
        extseed2[i] = seed[i];
        extseed3[i] = seed[i];
    }

    unsigned int coeffs_written = 0;
    unsigned int iteration = 0;

    uint32_t val;

    while (coeffs_written != NEWHOPE_N)
    {
        extseed0[NEWHOPE_SYMBYTES] = 4 * iteration;
        extseed1[NEWHOPE_SYMBYTES] = 4 *iteration + 1;
        extseed2[NEWHOPE_SYMBYTES] = 4 *iteration + 2;
        extseed3[NEWHOPE_SYMBYTES] = 4 *iteration + 3;

        if (extseed0[NEWHOPE_SYMBYTES] == 0) extseed0[NEWHOPE_SYMBYTES + 1]++;
        if (extseed1[NEWHOPE_SYMBYTES] == 0) extseed1[NEWHOPE_SYMBYTES + 1]++;
        if (extseed2[NEWHOPE_SYMBYTES] == 0) extseed2[NEWHOPE_SYMBYTES + 1]++;
        if (extseed3[NEWHOPE_SYMBYTES] == 0) extseed3[NEWHOPE_SYMBYTES + 1]++;

        shake128x4(buf, buf + SHAKE128_RATE, buf + 2 *SHAKE128_RATE, buf + 3 *SHAKE128_RATE, SHAKE128_RATE, extseed0, extseed1, extseed2, extseed3, NEWHOPE_SYMBYTES + 1);

        for (i = 0; i < 4 && coeffs_written < NEWHOPE_N; i++)
        {
            for (j = 0; j < SHAKE128_RATE - SAMPLE_BLOCK_SIZE && coeffs_written < NEWHOPE_N; j += 7)
            {
                sample_1 = ((uint32_t) buf[j + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 1 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 2 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &15) << 24));

                if (sample_1 < QA)
                {
                    a->coeffs[coeffs_written] = sample_1;
                    coeffs_written++;
                }

                if (coeffs_written == NEWHOPE_N) break;

                sample_2 = ((uint32_t) buf[j + 4 + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 5 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 6 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &240) << 20));

                if (sample_2 < QA)
                {
                    a->coeffs[coeffs_written] = sample_2;
                    coeffs_written++;
                }
            }
        }

        iteration++;
    }

    coeffs_written = 0;
    while (coeffs_written != NEWHOPE_N)
    {
        extseed0[NEWHOPE_SYMBYTES] = 4 * iteration;
        extseed1[NEWHOPE_SYMBYTES] = 4 *iteration + 1;
        extseed2[NEWHOPE_SYMBYTES] = 4 *iteration + 2;
        extseed3[NEWHOPE_SYMBYTES] = 4 *iteration + 3;

        if (extseed0[NEWHOPE_SYMBYTES] == 0) extseed0[NEWHOPE_SYMBYTES + 1]++;
        if (extseed1[NEWHOPE_SYMBYTES] == 0) extseed1[NEWHOPE_SYMBYTES + 1]++;
        if (extseed2[NEWHOPE_SYMBYTES] == 0) extseed2[NEWHOPE_SYMBYTES + 1]++;
        if (extseed3[NEWHOPE_SYMBYTES] == 0) extseed3[NEWHOPE_SYMBYTES + 1]++;

        shake128x4(buf, buf + SHAKE128_RATE, buf + 2 *SHAKE128_RATE, buf + 3 *SHAKE128_RATE, SHAKE128_RATE, extseed0, extseed1, extseed2, extseed3, NEWHOPE_SYMBYTES + 1);

        for (i = 0; i < 4 && coeffs_written < NEWHOPE_N; i++)
        {
            for (j = 0; j < SHAKE128_RATE - SAMPLE_BLOCK_SIZE && coeffs_written < NEWHOPE_N; j += 7)
            {
                sample_1 = ((uint32_t) buf[j + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 1 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 2 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &15) << 24));

                if (sample_1 < QB)
                {
                    b->coeffs[coeffs_written] = sample_1;
                    coeffs_written++;
                }

                if (coeffs_written == NEWHOPE_N) break;

                sample_2 = ((uint32_t) buf[j + 4 + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 5 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 6 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &240) << 20));

                if (sample_2 < QB)
                {
                    b->coeffs[coeffs_written] = sample_2;
                    coeffs_written++;
                }
            }
        }

        iteration++;
    }
}

/*************************************************
*Name:        montgomery_reduce
*
*Description: Montgomery reduction; given a 128-bit integer a, computes
*             64-bit integer congruent to a *R^-1 mod Q_AB,
*             where R=2^32
*
*Arguments:   - __int128 a: input integer to be reduced; has to be in {-Q_AB2^63,...,Q_AB2^63-1}
*
*Returns:     integer in {-Q_AB+1,...,Q_AB-1} congruent to a *R^-1 modulo Q_AB.
**************************************************/
int64_t montgomery_reduce_AB(__int128 a)
{
    __int128 t;
    int64_t u;

    u = a *(unsigned __int128) QINV_S64;

    t = (__int128) u *(__int128) Q_AB;
    t = a - t;
    t >>= 64;

    return t;
}

/*************************************************
 *Name:        barrett_reduce
 *
 *Description: Barrett reduction; given a 64-bit integer a, computes
 *             64-bit integer congruent to a mod Q_AB in {0,...,Q_AB}
 *
 *Arguments:   - int64_t a: input integer to be reduced
 *
 *Returns:     integer in {0,...,Q_AB} congruent to a modulo Q_AB.
 **************************************************/
int64_t barrett_reduce_AB(int64_t a)
{
    __int128 t;
    const __int128 v = ((__int128) 1U << BARRETT_REDUCE_FACTOR_AB) / (__int128) Q_AB + 1;

    t = v * a;
    t >>= BARRETT_REDUCE_FACTOR_AB;
    t *= (__int128) Q_AB;

    return a - t;
}

/*************************************************
 *Name:        poly_combine_56_AB
 *
 *Description: Given 2 poly_28 inputs, combine using CRT
 *
 *Arguments:   - poly_28 a: input polynomial in Q_A
 *             - poly_28 b: input polynomial in Q_B
 *             - poly_56 c: output polynomial in Q_AB
 *
 *Returns:     none
 **************************************************/
void poly_combine_56_AB(poly_28 *a, poly_28 *b, poly_56 *c) {
  int64_t temp;

  for (int i=0; i<NEWHOPE_N; i++) {
    c->coeffs[i] = montgomery_reduce_AB((__int128)a->coeffs[i]*(__int128)QB_QB_INV_A);
    c->coeffs[i] += montgomery_reduce_AB((__int128)b->coeffs[i]*(__int128)QA_QA_INV_B);
  }
}

/*************************************************
 *Name:        separate_56_AB
 *
 *Description: Given 1 poly_56 inputs, reduce elements by Q_A and Q_B
 *             into a and b, respectively.
 *
 *Arguments:   - poly_28 a: output polynomial in Q_A
 *             - poly_28 b: output polynomial in Q_B
  *            - poly_56 c: input polynomial in Q_AB
 *
 *Returns:     none
 **************************************************/
void separate_56_AB(poly_28 *a, poly_28 *b, poly_56 *c) {
  int64_t temp;

  for (int i=0; i<NEWHOPE_N; i++) {
    temp = montgomery_reduce_268369921(c->coeffs[i]);
    temp = montgomery_reduce_268369921(temp*TWO_32_2_A);
    a->coeffs[i] = temp;

    temp = montgomery_reduce_268361729(c->coeffs[i]);
    temp = montgomery_reduce_268361729(temp*TWO_32_2_B);
    b->coeffs[i] = temp;
  }
}


/*************************************************
 *Name:        create_product_point_AB
 *
 *Description: Takes in 2 poly_28 keys and seed of a poly_28, point_seed,
 *             generats 2 poly_28 in mod Q_A and Q_B, multiplies then as if they
 *             they are in the NTT domain, then computes the inverse NTT of the product.
 *             FInally combines the 2 poly_28 into a poly_56 mod Q_AB using CRT.
 *
 *Arguments:   - poly_28 *key_a: pointer to the poly_28 input mod Q_A
 *             - poly_28 *key_b: pointer to the poly_28 input mod Q_B
 *             - poly_56 *product_point_poly: pointer to the poly_56 product
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void create_product_point_AB(poly_28 *key_a, poly_28 *key_b, poly_56 *product, unsigned char *point_seed)
{
    int i;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        point_seed[i] += 1;
        if (point_seed[i] != 0) break;
    }

    poly_28 point_poly_a, point_poly_b, product_a, product_b;

    poly_uniform_ref_poly_28_AB(&point_poly_a, &point_poly_b, point_seed);

    poly_basemul_268369921(&product_a, key_a, &point_poly_a);
    poly_basemul_268361729(&product_b, key_b, &point_poly_b);

    poly_invntt_268369921(&product_a);
    poly_invntt_268361729(&product_b);

    poly_combine_56_AB(&product_a, &product_b, product);
}

/*************************************************
 *Name:        create_product_point_AB_avx
 *
 *Description: AVX2 form of create_product_point_AB.
 *             Takes in 2 poly_28 keys and seed of a poly_28, point_seed,
 *             generats 2 poly_28 in mod Q_A and Q_B, multiplies then as if they
 *             they are in the NTT domain, then computes the inverse NTT of the product.
 *             FInally combines the 2 poly_28 into a poly_56 mod Q_AB using CRT.
 *
 *Arguments:   - poly_28 *key_a: pointer to the poly_28 input mod Q_A
 *             - poly_28 *key_b: pointer to the poly_28 input mod Q_B
 *             - poly_28 *product_point_poly: pointer to the poly_28 product
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void create_product_point_AB_avx(poly_28 *key_a, poly_28 *key_b, poly_56 *product, unsigned char *point_seed)
{
    int i;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        point_seed[i] += 1;
        if (point_seed[i] != 0) break;
    }

    poly_28 point_poly_a, point_poly_b, product_a, product_b;

    poly_uniform_ref_poly_28_AB_avx(&point_poly_a, &point_poly_b, point_seed);

    poly_basemul_268369921(&product_a, key_a, &point_poly_a);
    poly_basemul_268361729(&product_b, key_b, &point_poly_b);

    poly_invntt_avx_268369921(&product_a);
    poly_invntt_avx_268361729(&product_b);

    poly_combine_56_AB(&product_a, &product_b, product);
}

/*************************************************
 *Name:        poly_uniform_ref_noise_seeds_pseudo_AB
 *
 *Description: Takes in a 32 bytes seed, generates a poly_56 with shake128 
 *             uniformly random elements in mod Q_AB. Differs than poly_uniform_ref_poly_28
 *             because it is used to generate the noise poly so the input extseed is different.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_56 *a: pointer to the poly_28 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_noise_seeds_pseudo_AB(poly_56 *a, const unsigned char *seed)
{
    unsigned int ctr = 0;
    uint64_t val;
    uint64_t state[25];
    uint8_t buf[SHAKE128_RATE];
    uint8_t extseed[(2 *NEWHOPE_SYMBYTES + 2)];
    int i, j, k;
    uint64_t bit_array[8] = {1, 2, 4, 8, 16, 32, 64, 128};

    for (i = 0; i < 2 *NEWHOPE_SYMBYTES + 2; i++) extseed[i] = 0;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        extseed[i] = seed[i];

    int coeffs_written = 0;
    int iteration = 0;
    uint8_t *a_byte = (int8_t*) a;
    uint64_t sample;

    while (coeffs_written != NEWHOPE_N)
    {
        if (iteration == 65536) printf("ERROR: poly_uniform_ref_poly_60: iteration hit its limit\n");
        for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        {
            extseed[i + NEWHOPE_SYMBYTES] += 1;
            if (extseed[i + NEWHOPE_SYMBYTES] != 0) break;
        }

        extseed[2 *NEWHOPE_SYMBYTES] = iteration; /*domain-separate the 16 independent calls */

        if (extseed[2 *NEWHOPE_SYMBYTES + 1] == 0) extseed[NEWHOPE_SYMBYTES + 1]++;

        shake128_absorb(state, extseed, 2*NEWHOPE_SYMBYTES + 2);
        shake128_squeezeblocks(buf, 1, state);

        for (j = 0; j <= SHAKE128_RATE - NOISE_MAX_BYTES_AB && coeffs_written < NEWHOPE_N; j += NOISE_MAX_BYTES_AB)
        {
          for (k = 0; k < 8 && coeffs_written < NEWHOPE_N; k ++) {
              sample = ((uint64_t) buf[j+k] | ((uint64_t)(buf[j + 8] &bit_array[k]) << (8-k)));
              if (sample < NOISE_MAX_AB)
              {
                  a->coeffs[coeffs_written] = sample;
                  coeffs_written++;
              }
          }

        }

        iteration++;
    }
}

/*************************************************
 *Name:        poly_uniform_ref_noise_seeds_pseudo_AB_avx
 *
 *Description: AVX2 form of poly_uniform_ref_noise_seeds_pseudo_AB.
 *             Takes in a 32 bytes seed, generates a poly_56 with shake128 
 *             uniformly random elements in mod Q_AB. Differs than poly_uniform_ref_poly_28
 *             because it is used to generate the noise poly so the input extseed is different.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_56 *a: pointer to the poly_28 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_noise_seeds_pseudo_AB_avx(poly_56 *a, const unsigned char *seed)
{
    uint8_t buf[4 *SHAKE128_RATE];
    uint8_t extseed0[2 *NEWHOPE_SYMBYTES + 2];
    uint8_t extseed1[2 *NEWHOPE_SYMBYTES + 2];
    uint8_t extseed2[2 *NEWHOPE_SYMBYTES + 2];
    uint8_t extseed3[2 *NEWHOPE_SYMBYTES + 2];
    int i, j, k;
    uint64_t bit_array[8] = {1, 2, 4, 8, 16, 32, 64, 128};

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        extseed0[i] = seed[i];
        extseed1[i] = seed[i];
        extseed2[i] = seed[i];
        extseed3[i] = seed[i];
    }

    unsigned int coeffs_written = 0;
    unsigned int iteration = 0;

    uint32_t val;
    uint64_t sample;

    uint64_t used = 0;
    uint64_t tossed = 0;

    while (coeffs_written != NEWHOPE_N)
    {
        if (iteration == 65536) printf("ERROR: poly_uniform_ref_poly_28: iteration hit its limit\n");

        for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        {
            extseed0[i + NEWHOPE_SYMBYTES] += 1;
            if (extseed0[i + NEWHOPE_SYMBYTES] != 0) break;
        }

        for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        {
            extseed1[i + NEWHOPE_SYMBYTES] += 1;
            if (extseed1[i + NEWHOPE_SYMBYTES] != 0) break;
        }

        for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        {
            extseed2[i + NEWHOPE_SYMBYTES] += 1;
            if (extseed2[i + NEWHOPE_SYMBYTES] != 0) break;
        }

        for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        {
            extseed2[i + NEWHOPE_SYMBYTES] += 1;
            if (extseed2[i + NEWHOPE_SYMBYTES] != 0) break;
        }

        extseed0[2 *NEWHOPE_SYMBYTES] = 4 * iteration;
        extseed1[2 *NEWHOPE_SYMBYTES] = 4 *iteration + 1;
        extseed2[2 *NEWHOPE_SYMBYTES] = 4 *iteration + 2;
        extseed3[2 *NEWHOPE_SYMBYTES] = 4 *iteration + 3;

        if (extseed0[2 *NEWHOPE_SYMBYTES] == 0) extseed0[2 *NEWHOPE_SYMBYTES + 1]++;
        if (extseed1[2 *NEWHOPE_SYMBYTES] == 0) extseed1[2 *NEWHOPE_SYMBYTES + 1]++;
        if (extseed2[2 *NEWHOPE_SYMBYTES] == 0) extseed2[2 *NEWHOPE_SYMBYTES + 1]++;
        if (extseed3[2 *NEWHOPE_SYMBYTES] == 0) extseed3[2 *NEWHOPE_SYMBYTES + 1]++;

        shake128x4(buf, buf + SHAKE128_RATE, buf + 2 *SHAKE128_RATE, buf + 3 *SHAKE128_RATE, SHAKE128_RATE, extseed0, extseed1, extseed2, extseed3, NEWHOPE_SYMBYTES + 1);

        for (i = 0; i < 4 && coeffs_written < NEWHOPE_N; i++)
        {   
            for (j = 0; j <= SHAKE128_RATE - NOISE_MAX_BYTES_AB && coeffs_written < NEWHOPE_N; j += NOISE_MAX_BYTES_AB)
            {
              for (k = 0; k < 8 && coeffs_written < NEWHOPE_N; k ++) {
                  sample = ((uint64_t) buf[j+k+ i *SHAKE128_RATE] | ((uint64_t)(buf[j + 8+ i *SHAKE128_RATE] &bit_array[k]) << (8-k)));
                  if (sample < NOISE_MAX_AB)
                  {
                      a->coeffs[coeffs_written] = sample;
                      coeffs_written++;
                  }
              }

            }
        }

        iteration++;
    }
}

/*************************************************
 *Name:        convert_to_39_bits
 *
 *Description: Takes in a byte pointer, converts bytes into 39 bit chucks into 40 bit chunks      
 *
 *Arguments:   - uint8_t *in: pointer to input byte array
 *             - uint8_t *out: pointer to output byte array
 *             - int size: size of input array
 *
 *Returns:     None
 **************************************************/
int convert_to_39_bits(uint8_t *in, uint8_t *out, int size) {
    if (size%39 != 0) return -1;

    int output_amount = 0;


    int8_t leftover = 0;
    int i, j;
    for (i=0; i<size; i+=39) {
        for (j=0; j<35; j+=5) {
            out[output_amount] = in[i+j];
            out[output_amount+1] = in[i+j+1];
            out[output_amount+2] = in[i+j+2];
            out[output_amount+3] = in[i+j+3];
            out[output_amount+4] = in[i+j+4]&127;

            leftover = (leftover<<1)|(in[i+j+4]>>7);
            output_amount += 5;
        }

        out[output_amount] = in[i+35];
        out[output_amount+1] = in[i+36];
        out[output_amount+2] = in[i+37];
        out[output_amount+3] = in[i+38];
        out[output_amount+4] = leftover;
        output_amount +=5;

        leftover = 0;
    }

    return output_amount;
}

/*************************************************
 *Name:        convert_back_from_39_bits
 *
 *Description: Inverse of convert_to_39_bits    
 *
 *Arguments:   - uint8_t *in: pointer to input byte array
 *             - uint8_t *out: pointer to output byte array
 *             - int size: size of input array
 *
 *Returns:     None
 **************************************************/
int convert_back_from_39_bits(uint8_t *in, uint8_t *out, int size) {
    if (size%8 != 0) return -1;
    int output_len = 0;

    int i=0;
    uint8_t leftover;
    for (i=0; i<size; i+=40) {
        for (int j=0; j<39; j++){
            out[output_len+j] = in[i+j];
        }
        leftover = in[i+39];
        for (int j=34; j>0; j-=5){
            out[output_len+j] |= (leftover&1)<<7;
            leftover = (leftover>>1);
        }
        
        output_len += 39;
    }

    return output_len;
}

/*************************************************
 *Name:        kh_prf_re_encrypt_2
 *
 *Description: KH_PRF to re_encrypt buf using key_point_poly's. Simliar to
 *             kh_prf_encrypt doesn't set the bottom 2 bytes of each coefficient
 *             to be empty.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the delta of the new and old key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the delta of the new and old key mod Q_B
 *             - uint8_t *buf: pointer to the old ciphertext
 *             - uint8_t *out: pointer to the new ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_re_encrypt_2_AB(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_56 product_poly;
    poly_56 noise_poly;

    uint64_t guassian_output;

    int bytes_processed = 0;

    while (bytes_processed < size)
    {
        create_product_point_AB(key_point_poly_a, key_point_poly_b, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_AB(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {

            uint64_t sample_1 = ((uint64_t) buf[bytes_processed] |
                ((uint64_t) buf[bytes_processed + 1] << 8) |
                ((uint64_t) buf[bytes_processed + 2] << 16) |
                ((uint64_t) buf[bytes_processed + 3] << 24) |
                ((uint64_t) buf[bytes_processed + 4] << 32) |
                ((uint64_t) buf[bytes_processed + 5] << 40) |
                ((uint64_t) buf[bytes_processed + 6] << 48) );
            uint64_t sample_2 = ((uint64_t) buf[bytes_processed +7] |
                ((uint64_t) buf[bytes_processed + 8] << 8) |
                ((uint64_t) buf[bytes_processed + 9] << 16) |
                ((uint64_t) buf[bytes_processed + 10] << 24) |
                ((uint64_t) buf[bytes_processed + 11] << 32) |
                ((uint64_t) buf[bytes_processed + 12] << 40) |
                ((uint64_t) buf[bytes_processed + 13] << 48) );

            sample_1 = barrett_reduce_AB(sample_1 + (uint64_t) product_poly.coeffs[i] + (uint64_t) noise_poly.coeffs[i]);
            sample_2 = barrett_reduce_AB(sample_2 + (uint64_t) product_poly.coeffs[i + 1] + (uint64_t) noise_poly.coeffs[i + 1]);

            out[bytes_processed] = sample_1 &255ul;
            out[bytes_processed + 1] = (sample_1 &(255ul << 8)) >> 8;
            out[bytes_processed + 2] = (sample_1 &(255ul << 16)) >> 16;
            out[bytes_processed + 3] = (sample_1 &(255ul << 24)) >> 24;
            out[bytes_processed + 4] = (sample_1 &(255ul << 32)) >> 32;
            out[bytes_processed + 5] = (sample_1 &(255ul << 40)) >> 40;
            out[bytes_processed + 6] = (sample_1 &(255ul << 48)) >> 48;

            out[bytes_processed + 7] = sample_2 &255ul;
            out[bytes_processed + 8] = (sample_2 &(255ul << 8)) >> 8;
            out[bytes_processed + 9] = (sample_2 &(255ul << 16)) >> 16;
            out[bytes_processed + 10] = (sample_2 &(255ul << 24)) >> 24;
            out[bytes_processed + 11] = (sample_2 &(255ul << 32)) >> 32;
            out[bytes_processed + 12] = (sample_2 &(255ul << 40)) >> 40;
            out[bytes_processed + 13] = (sample_2 &(255ul << 48)) >> 48;

            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_processed;
}

/*************************************************
 *Name:        kh_prf_re_encrypt_2_AB_avx
 *
 *Description: AVX form of kh_prf_re_encrypt_2_AB.
 *             KH_PRF to re_encrypt buf using key_point_poly's. Simliar to
 *             kh_prf_encrypt doesn't set the bottom 2 bytes of each coefficient
 *             to be empty.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the delta of the new and old key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the delta of the new and old key mod Q_B
 *             - uint8_t *buf: pointer to the old ciphertext
 *             - uint8_t *out: pointer to the new ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_re_encrypt_2_AB_avx(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_56 product_poly;
    poly_56 noise_poly;

    uint64_t guassian_output;

    int bytes_processed = 0;

    while (bytes_processed < size)
    {
        create_product_point_AB_avx(key_point_poly_a, key_point_poly_b, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_AB_avx(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {

            uint64_t sample_1 = ((uint64_t) buf[bytes_processed] |
                ((uint64_t) buf[bytes_processed + 1] << 8) |
                ((uint64_t) buf[bytes_processed + 2] << 16) |
                ((uint64_t) buf[bytes_processed + 3] << 24) |
                ((uint64_t) buf[bytes_processed + 4] << 32) |
                ((uint64_t) buf[bytes_processed + 5] << 40) |
                ((uint64_t) buf[bytes_processed + 6] << 48) );
            uint64_t sample_2 = ((uint64_t) buf[bytes_processed +7] |
                ((uint64_t) buf[bytes_processed + 8] << 8) |
                ((uint64_t) buf[bytes_processed + 9] << 16) |
                ((uint64_t) buf[bytes_processed + 10] << 24) |
                ((uint64_t) buf[bytes_processed + 11] << 32) |
                ((uint64_t) buf[bytes_processed + 12] << 40) |
                ((uint64_t) buf[bytes_processed + 13] << 48) );

            sample_1 = barrett_reduce_AB(sample_1 + (uint64_t) product_poly.coeffs[i] + (uint64_t) noise_poly.coeffs[i]);
            sample_2 = barrett_reduce_AB(sample_2 + (uint64_t) product_poly.coeffs[i + 1] + (uint64_t) noise_poly.coeffs[i + 1]);

            out[bytes_processed] = sample_1 &255ul;
            out[bytes_processed + 1] = (sample_1 &(255ul << 8)) >> 8;
            out[bytes_processed + 2] = (sample_1 &(255ul << 16)) >> 16;
            out[bytes_processed + 3] = (sample_1 &(255ul << 24)) >> 24;
            out[bytes_processed + 4] = (sample_1 &(255ul << 32)) >> 32;
            out[bytes_processed + 5] = (sample_1 &(255ul << 40)) >> 40;
            out[bytes_processed + 6] = (sample_1 &(255ul << 48)) >> 48;

            out[bytes_processed + 7] = sample_2 &255ul;
            out[bytes_processed + 8] = (sample_2 &(255ul << 8)) >> 8;
            out[bytes_processed + 9] = (sample_2 &(255ul << 16)) >> 16;
            out[bytes_processed + 10] = (sample_2 &(255ul << 24)) >> 24;
            out[bytes_processed + 11] = (sample_2 &(255ul << 32)) >> 32;
            out[bytes_processed + 12] = (sample_2 &(255ul << 40)) >> 40;
            out[bytes_processed + 13] = (sample_2 &(255ul << 48)) >> 48;

            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_processed;
}

/*************************************************
 *Name:        kh_prf_encrypt_2_AB_m
 *
 *Description: KH_PRF to encrypt buf using key_point_poly_a and key_point_poly_b. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the key mod Q_B
 *             - uint8_t *buf: pointer to the message
 *             - uint8_t *out: pointer to the ciphertext
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_encrypt_2_AB_m(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_56 product_poly;
    poly_56 noise_poly;

    uint64_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;

    uint8_t converted[C_MESSAGE_BLOCK_SIZE];
    int curr_block_size;
    while (bytes_processed < size)
    {
        curr_block_size = 0;;
        if (size < MESSAGE_BLOCK_SIZE) {
            curr_block_size = size*39/(8*5);
        }
        else {
            curr_block_size = MESSAGE_BLOCK_SIZE;
        }
        convert_to_39_bits(buf, converted, curr_block_size);
        create_product_point_AB(key_point_poly_a, key_point_poly_b, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_AB(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {

            uint64_t sample_1 = ((uint64_t) NOISE_MAX |
                ((uint64_t) converted[(bytes_processed)%(C_MESSAGE_BLOCK_SIZE)] << 16) |
                ((uint64_t) converted[(bytes_processed+1)%(C_MESSAGE_BLOCK_SIZE)] << 24) |
                ((uint64_t) converted[(bytes_processed+2)%(C_MESSAGE_BLOCK_SIZE)] << 32) |
                ((uint64_t) converted[(bytes_processed+3)%(C_MESSAGE_BLOCK_SIZE)] << 40) |
                ((uint64_t) converted[(bytes_processed+4)%(C_MESSAGE_BLOCK_SIZE)] << 48) );
            uint64_t sample_2 = ((uint64_t) NOISE_MAX |
                ((uint64_t) converted[(bytes_processed+5)%(C_MESSAGE_BLOCK_SIZE)] << 16) |
                ((uint64_t) converted[(bytes_processed+6)%(C_MESSAGE_BLOCK_SIZE)] << 24) |
                ((uint64_t) converted[(bytes_processed+7)%(C_MESSAGE_BLOCK_SIZE)] << 32) |
                ((uint64_t) converted[(bytes_processed+8)%(C_MESSAGE_BLOCK_SIZE)] << 40) |
                ((uint64_t) converted[(bytes_processed+9)%(C_MESSAGE_BLOCK_SIZE)] << 48) );

            sample_1 = barrett_reduce_AB(sample_1 + (uint64_t) product_poly.coeffs[i] + (uint64_t) noise_poly.coeffs[i]);
            sample_2 = barrett_reduce_AB(sample_2+ (uint64_t) product_poly.coeffs[i + 1] +(uint64_t) noise_poly.coeffs[i + 1]);

            out[bytes_written] = sample_1 &255ul;
            out[bytes_written + 1] = (sample_1 &(255ul << 8)) >> 8;
            out[bytes_written + 2] = (sample_1 &(255ul << 16)) >> 16;
            out[bytes_written + 3] = (sample_1 &(255ul << 24)) >> 24;
            out[bytes_written + 4] = (sample_1 &(255ul << 32)) >> 32;
            out[bytes_written + 5] = (sample_1 &(255ul << 40)) >> 40;
            out[bytes_written + 6] = (sample_1 &(255ul << 48)) >> 48;

            out[bytes_written + 7] = sample_2 &255ul;
            out[bytes_written + 8] = (sample_2 &(255ul << 8)) >> 8;
            out[bytes_written + 9] = (sample_2 &(255ul << 16)) >> 16;
            out[bytes_written + 10] = (sample_2 &(255ul << 24)) >> 24;
            out[bytes_written + 11] = (sample_2 &(255ul << 32)) >> 32;
            out[bytes_written + 12] = (sample_2 &(255ul << 40)) >> 40;
            out[bytes_written + 13] = (sample_2 &(255ul << 48)) >> 48;

            bytes_processed += C_PAD_SIZE;
            bytes_written += SAMPLE_BLOCK_SIZE;
        }
        buf+=curr_block_size;
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_encrypt_2_AB_m_avx
 *
 *Description: AVX implementation of kh_prf_encrypt_2_AB_m.
 *             KH_PRF to encrypt buf using key_point_poly_a and key_point_poly_b. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the key mod Q_B
 *             - uint8_t *buf: pointer to the message
 *             - uint8_t *out: pointer to the ciphertext
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_encrypt_2_AB_m_avx(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_56 product_poly;
    poly_56 noise_poly;

    uint64_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;

    uint8_t converted[C_MESSAGE_BLOCK_SIZE];
    while (bytes_processed < size)
    {
        if (size < MESSAGE_BLOCK_SIZE) {
            convert_to_39_bits(buf, converted, size*39/(8*5));
        }
        else {
            convert_to_39_bits(buf, converted, MESSAGE_BLOCK_SIZE);
        }
        create_product_point_AB_avx(key_point_poly_a, key_point_poly_b, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_AB_avx(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {

            uint64_t sample_1 = ((uint64_t) NOISE_MAX |
                ((uint64_t) converted[(bytes_processed)%(C_MESSAGE_BLOCK_SIZE)] << 16) |
                ((uint64_t) converted[(bytes_processed+1)%(C_MESSAGE_BLOCK_SIZE)] << 24) |
                ((uint64_t) converted[(bytes_processed+2)%(C_MESSAGE_BLOCK_SIZE)] << 32) |
                ((uint64_t) converted[(bytes_processed+3)%(C_MESSAGE_BLOCK_SIZE)] << 40) |
                ((uint64_t) converted[(bytes_processed+4)%(C_MESSAGE_BLOCK_SIZE)] << 48) );
            uint64_t sample_2 = ((uint64_t) NOISE_MAX |
                ((uint64_t) converted[(bytes_processed+5)%(C_MESSAGE_BLOCK_SIZE)] << 16) |
                ((uint64_t) converted[(bytes_processed+6)%(C_MESSAGE_BLOCK_SIZE)] << 24) |
                ((uint64_t) converted[(bytes_processed+7)%(C_MESSAGE_BLOCK_SIZE)] << 32) |
                ((uint64_t) converted[(bytes_processed+8)%(C_MESSAGE_BLOCK_SIZE)] << 40) |
                ((uint64_t) converted[(bytes_processed+9)%(C_MESSAGE_BLOCK_SIZE)] << 48) );

            sample_1 = barrett_reduce_AB(sample_1 + (uint64_t) product_poly.coeffs[i] + (uint64_t) noise_poly.coeffs[i]);
            sample_2 = barrett_reduce_AB(sample_2+ (uint64_t) product_poly.coeffs[i + 1] +(uint64_t) noise_poly.coeffs[i + 1]);

            out[bytes_written] = sample_1 &255ul;
            out[bytes_written + 1] = (sample_1 &(255ul << 8)) >> 8;
            out[bytes_written + 2] = (sample_1 &(255ul << 16)) >> 16;
            out[bytes_written + 3] = (sample_1 &(255ul << 24)) >> 24;
            out[bytes_written + 4] = (sample_1 &(255ul << 32)) >> 32;
            out[bytes_written + 5] = (sample_1 &(255ul << 40)) >> 40;
            out[bytes_written + 6] = (sample_1 &(255ul << 48)) >> 48;

            out[bytes_written + 7] = sample_2 &255ul;
            out[bytes_written + 8] = (sample_2 &(255ul << 8)) >> 8;
            out[bytes_written + 9] = (sample_2 &(255ul << 16)) >> 16;
            out[bytes_written + 10] = (sample_2 &(255ul << 24)) >> 24;
            out[bytes_written + 11] = (sample_2 &(255ul << 32)) >> 32;
            out[bytes_written + 12] = (sample_2 &(255ul << 40)) >> 40;
            out[bytes_written + 13] = (sample_2 &(255ul << 48)) >> 48;

            bytes_processed += C_PAD_SIZE;
            bytes_written += SAMPLE_BLOCK_SIZE;
        }
        buf+=MESSAGE_BLOCK_SIZE;
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_decrypt_2_AB_m
 *
 *Description: KH_PRF to decrypt buf using key_point_poly_a and key_point_poly_b. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the key mod Q_B
 *             - uint8_t *buf: pointer to the ciphertext
 *             - uint8_t *out: pointer to the decrypted message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int kh_prf_decrypt_2_AB_m(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_56 product_poly;

    uint64_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;
    int converted_written = 0;

    uint8_t converted[C_MESSAGE_BLOCK_SIZE];
    while (bytes_processed < size)
    {
        create_product_point_AB(key_point_poly_a, key_point_poly_b, &product_poly, (unsigned char *) &point_seed);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {

            uint64_t sample_1 = ((uint64_t) buf[bytes_processed] |
                ((uint64_t) buf[bytes_processed + 1] << 8) |
                ((uint64_t) buf[bytes_processed + 2] << 16) |
                ((uint64_t) buf[bytes_processed + 3] << 24) |
                ((uint64_t) buf[bytes_processed + 4] << 32) |
                ((uint64_t) buf[bytes_processed + 5] << 40) |
                ((uint64_t) (buf[bytes_processed + 6]) << 48) );
            uint64_t sample_2 = ((uint64_t) buf[bytes_processed + 7] |
                ((uint64_t) buf[bytes_processed + 8] << 8) |
                ((uint64_t) buf[bytes_processed + 9] << 16) |
                ((uint64_t) buf[bytes_processed + 10] << 24) |
                ((uint64_t) buf[bytes_processed + 11] << 32) |
                ((uint64_t) buf[bytes_processed + 12] << 40) |
                ((uint64_t) (buf[bytes_processed + 13]) << 48) );            

            sample_1 = barrett_reduce_AB(sample_1 - (uint64_t) product_poly.coeffs[i]);
            sample_2 = barrett_reduce_AB(sample_2 - (uint64_t) product_poly.coeffs[i + 1]);

            converted[(converted_written)%10240] = (sample_1 &(255ul << 16)) >> 16;
            converted[(converted_written+1)%10240] = (sample_1 &(255ul << 24)) >> 24;
            converted[(converted_written+2)%10240] = (sample_1 &(255ul << 32)) >> 32;
            converted[(converted_written+3)%10240] = (sample_1 &(255ul << 40)) >> 40;
            converted[(converted_written+4)%10240] = (sample_1 &(255ul << 48)) >> 48;

            converted[(converted_written+5)%10240] = (sample_2 &(255ul << 16)) >> 16;
            converted[(converted_written+6)%10240] = (sample_2 &(255ul << 24)) >> 24;
            converted[(converted_written+7)%10240] = (sample_2 &(255ul << 32)) >> 32;
            converted[(converted_written+8)%10240] = (sample_2 &(255ul << 40)) >> 40;
            converted[(converted_written+9)%10240] = (sample_2 &(255ul << 48)) >> 48;

            bytes_processed += SAMPLE_BLOCK_SIZE;
            converted_written += C_PAD_SIZE;

            if (i%8==6) bytes_written += PAD_SIZE;

        }
        convert_back_from_39_bits(converted,out, converted_written);
        converted_written = 0;
        out+=MESSAGE_BLOCK_SIZE;
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_decrypt_2_AB_m_avx
 *
 *Description: AVX form of kh_prf_decrypt_2_AB_m.
 *             KH_PRF to decrypt buf using key_point_poly_a and key_point_poly_b. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the key mod Q_B
 *             - uint8_t *buf: pointer to the ciphertext
 *             - uint8_t *out: pointer to the decrypted message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int kh_prf_decrypt_2_AB_m_avx(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_56 product_poly;

    uint64_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;
    int converted_written = 0;

    uint8_t converted[C_MESSAGE_BLOCK_SIZE];
    while (bytes_processed < size)
    {
        create_product_point_AB_avx(key_point_poly_a, key_point_poly_b, &product_poly, (unsigned char *) &point_seed);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {

            uint64_t sample_1 = ((uint64_t) buf[bytes_processed] |
                ((uint64_t) buf[bytes_processed + 1] << 8) |
                ((uint64_t) buf[bytes_processed + 2] << 16) |
                ((uint64_t) buf[bytes_processed + 3] << 24) |
                ((uint64_t) buf[bytes_processed + 4] << 32) |
                ((uint64_t) buf[bytes_processed + 5] << 40) |
                ((uint64_t) (buf[bytes_processed + 6]) << 48) );
            uint64_t sample_2 = ((uint64_t) buf[bytes_processed + 7] |
                ((uint64_t) buf[bytes_processed + 8] << 8) |
                ((uint64_t) buf[bytes_processed + 9] << 16) |
                ((uint64_t) buf[bytes_processed + 10] << 24) |
                ((uint64_t) buf[bytes_processed + 11] << 32) |
                ((uint64_t) buf[bytes_processed + 12] << 40) |
                ((uint64_t) (buf[bytes_processed + 13]) << 48) );            

            sample_1 = barrett_reduce_AB(sample_1 - (uint64_t) product_poly.coeffs[i]);
            sample_2 = barrett_reduce_AB(sample_2 - (uint64_t) product_poly.coeffs[i + 1]);

            converted[converted_written] = (sample_1 &(255ul << 16)) >> 16;
            converted[converted_written+1] = (sample_1 &(255ul << 24)) >> 24;
            converted[converted_written+2] = (sample_1 &(255ul << 32)) >> 32;
            converted[converted_written+3] = (sample_1 &(255ul << 40)) >> 40;
            converted[converted_written+4] = (sample_1 &(255ul << 48)) >> 48;

            converted[converted_written+5] = (sample_2 &(255ul << 16)) >> 16;
            converted[converted_written+6] = (sample_2 &(255ul << 24)) >> 24;
            converted[converted_written+7] = (sample_2 &(255ul << 32)) >> 32;
            converted[converted_written+8] = (sample_2 &(255ul << 40)) >> 40;
            converted[converted_written+9] = (sample_2 &(255ul << 48)) >> 48;

            bytes_processed += SAMPLE_BLOCK_SIZE;
            converted_written += C_PAD_SIZE;

            if (i%8==6) bytes_written += PAD_SIZE;
        }
        convert_back_from_39_bits(converted,out, converted_written);
        converted_written = 0;;
        out+=MESSAGE_BLOCK_SIZE;
        //bytes_written += MESSAGE_BLOCK_SIZE;
    }
    return bytes_written;
}

/*************************************************
 *Name:        UAE_Keygen
 *
 *Description: Generates a random AE_key with no input.
 *
 *Arguments:   - int8_t *AE_key: pointer to the AE_key generated
 *
 *Returns:     None
 **************************************************/
void UAE_Keygen(int8_t *AE_key)
{
    RAND_bytes(AE_key, AE_KEY_LEN);
}

/*************************************************
 *Name:        lwe_gen_key
 *
 *Description: Generated 2 random poly_28 with no input.
 *
 *Arguments:   - poly_28 *key_point_polya: pointer to the poly_28 generated mod Q_A
 *             - poly_28 *key_point_polyb: pointer to the poly_28 generated mod Q_B
 *
 *Returns:     None
 **************************************************/
void lwe_gen_key(poly_28 *key_point_polya, poly_28 *key_point_polyb)
{
    uint8_t key_seed[NEWHOPE_SYMBYTES];
    RAND_bytes(key_seed, NEWHOPE_SYMBYTES);
    poly_uniform_ref_poly_28_AB(key_point_polya, key_point_polyb, key_seed);
}

/*************************************************
 *Name:        lwe_gen_key
 *
 *Description: AVX form of lwe_gen_key. Generated 2 random poly_28 with no input.
 *
 *Arguments:   - poly_28 *key_point_polya: pointer to the poly_28 generated mod Q_A
 *             - poly_28 *key_point_polyb: pointer to the poly_28 generated mod Q_B
 *
 *Returns:     None
 **************************************************/
void lwe_gen_key_avx(poly_28 *key_point_polya, poly_28 *key_point_polyb)
{
    uint8_t key_seed[NEWHOPE_SYMBYTES];
    RAND_bytes(key_seed, NEWHOPE_SYMBYTES);
    poly_uniform_ref_poly_28_AB_avx(key_point_polya, key_point_polyb, key_seed);
}

/*************************************************
 *Name:        poly_uniform_ref_message
 *
 *Description: Computes the shake128 hash of a message (seed) given its size and outputs to a.       
 *
 *Arguments:   - unsigned char *a: pointer to the output
 *             - const unsigned char *seed: pointer to the message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_message(unsigned char *a, const unsigned char *seed, unsigned int size)
{
    unsigned int ctr = 0;
    uint32_t val;
    uint64_t state[25];
    uint8_t buf[SHAKE128_RATE];
    int i, j;

    unsigned int bytes_written = 0;
    shake128_absorb(state, seed, size);

    shake128_squeezeblocks(buf, 1, state);
    for (i = 0; i < SHAKE128_RATE; i++)
    {
        a[i] = buf[i];
    }
}

/*************************************************
 *Name:        UAE_Encrypt
 *
 *Description: Encrypts message using AE_key and outputs ciphertext_hat and ciphertext.
 *
 *Arguments:   - int8_t *AE_key: pointer to the AE_key generated
 *             - uint8_t *message: pointer to the message
 *             - UAE_lwe_ctx_header *ciphertext_hat: pointer to the generated ciphertext_hat
 *             - uint8_t *ciphertext: pointer to the generated ciphertext
 *             - unsigned int size: size of the message in bytes
 *
 *Returns:     The length of the encryped ciphertext in bytes.
 **************************************************/

int UAE_Encrypt(int8_t *AE_key, uint8_t *message, UAE_lwe_ctx_header *ciphertext_hat, uint8_t *ciphertext, unsigned int size)
{
    UAE_lwe_data_header data_header;
    lwe_gen_key(&data_header.poly_keya, &data_header.poly_keyb);

    int padded_size = pad_array(message, size);

    poly_uniform_ref_message(data_header.hash, message, padded_size);
    RAND_bytes(ciphertext_hat->iv, IV_LEN);
    int ctx_header_length = gcm_encrypt((uint8_t*) &data_header, sizeof(UAE_lwe_data_header),
        AE_key,
        ciphertext_hat->iv, IV_LEN,
        ciphertext_hat->ctx,
        ciphertext_hat->tag);

    int c_padded_size = padded_size*(8*5)/39;
    int output_len = kh_prf_encrypt_2_AB_m(&data_header.poly_keya, &data_header.poly_keyb, message, ciphertext, c_padded_size);

    return output_len;
}

/*************************************************
 *Name:        UAE_Encrypt_avx
 *
 *Description: AVX2 version of UAE_Encrypt. Encrypts message using AE_key and outputs ciphertext_hat and ciphertext.
 *
 *Arguments:   - int8_t *AE_key: pointer to the AE_key generated
 *             - uint8_t *message: pointer to the message
 *             - UAE_lwe_ctx_header *ciphertext_hat: pointer to the generated ciphertext_hat
 *             - uint8_t *ciphertext: pointer to the generated ciphertext
 *             - unsigned int size: size of the message in bytes
 *
 *Returns:     The length of the encryped ciphertext in bytes.
 **************************************************/
int UAE_Encrypt_avx(int8_t *AE_key, uint8_t *message, UAE_lwe_ctx_header *ciphertext_hat, uint8_t *ciphertext, unsigned int size)
{
    UAE_lwe_data_header data_header;
    lwe_gen_key_avx(&data_header.poly_keya, &data_header.poly_keyb);

    int padded_size = pad_array(message, size);

    poly_uniform_ref_message(data_header.hash, message, padded_size);
    RAND_bytes(ciphertext_hat->iv, IV_LEN);
    int ctx_header_length = gcm_encrypt((uint8_t*) &data_header, sizeof(UAE_lwe_data_header),
        AE_key,
        ciphertext_hat->iv, IV_LEN,
        ciphertext_hat->ctx,
        ciphertext_hat->tag);

    int c_padded_size = padded_size*(8*5)/39;
    int output_len = kh_prf_encrypt_2_AB_m_avx(&data_header.poly_keya, &data_header.poly_keyb, message, ciphertext, c_padded_size);

    return output_len;
}

/*************************************************
 *Name:        UAE_Decrypt
 *
 *Description: Decrypts UAE_Decrypt using AE_key and ciphertext_hat, outputs to decrypted_message.
 *
 *Arguments:   - int8_t *AE_key: pointer to the AE_key generated
 *             - uint8_t *decrypted_message: pointer to the decrypted message
 *             - UAE_lwe_ctx_header *ciphertext_hat: pointer to the ciphertext_hat
 *             - uint8_t *ciphertext: pointer to the ciphertext
 *             - unsigned int size: size of the message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int UAE_Decrypt(int8_t *AE_key, uint8_t *decrypted_message, UAE_lwe_ctx_header *ciphertext_hat, uint8_t *ciphertext, unsigned int size)
{
    UAE_lwe_data_header data_header;

    int ctx_header_length = gcm_decrypt(ciphertext_hat->ctx, sizeof(UAE_lwe_data_header),
        ciphertext_hat->tag,
        AE_key,
        ciphertext_hat->iv, IV_LEN,
        (uint8_t*) &data_header);
    if (ctx_header_length != sizeof(UAE_lwe_data_header))
    {
        printf("ERROR decrypting header\n");
        return -1;
    }

    int output_len = kh_prf_decrypt_2_AB_m(&data_header.poly_keya, &data_header.poly_keyb, ciphertext, decrypted_message, size);

    uint8_t hash[SHAKE128_RATE];
    poly_uniform_ref_message(hash, decrypted_message, output_len);

    for (int i = 0; i < SHAKE128_RATE; i++)
    {
        if (data_header.hash[i] != hash[i])
        {
            printf("HASH DOES NOT MATCH %d: %u %u\n",i,hash[i],data_header.hash[i]);
            return -1;
        }
    }

    int unpadded_size = unpad_array(decrypted_message, output_len);
    return unpadded_size;
}

 /*************************************************
 *Name:        UAE_Decrypt_avx
 *
 *Description: AVX2 version of UAE_Decrypt. Decrypts UAE_Decrypt using AE_key and ciphertext_hat, outputs to decrypted_message.
 *
 *Arguments:   - int8_t *AE_key: pointer to the AE_key generated
 *             - uint8_t *decrypted_message: pointer to the decrypted message
 *             - UAE_lwe_ctx_header *ciphertext_hat: pointer to the ciphertext_hat
 *             - uint8_t *ciphertext: pointer to the ciphertext
 *             - unsigned int size: size of the message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int UAE_Decrypt_avx(int8_t *AE_key, uint8_t *decrypted_message, UAE_lwe_ctx_header *ciphertext_hat, uint8_t *ciphertext, unsigned int size)
{
    UAE_lwe_data_header data_header;

    int ctx_header_length = gcm_decrypt(ciphertext_hat->ctx, sizeof(UAE_lwe_data_header),
        ciphertext_hat->tag,
        AE_key,
        ciphertext_hat->iv, IV_LEN,
        (uint8_t*) &data_header);
    if (ctx_header_length != sizeof(UAE_lwe_data_header))
    {
        printf("ERROR decrypting header\n");
        return -1;
    }

    int output_len = kh_prf_decrypt_2_AB_m_avx(&data_header.poly_keya, &data_header.poly_keyb, ciphertext, decrypted_message, size);
    uint8_t hash[SHAKE128_RATE];
    poly_uniform_ref_message(hash, decrypted_message, output_len);

    for (int i = 0; i < SHAKE128_RATE; i++)
    {
        if (data_header.hash[i] != hash[i])
        {
            printf("HASH DOES NOT MATCH %d: %u %u\n",i,hash[i],data_header.hash[i]);
            return -1;
        }
    }

    int unpadded_size = unpad_array(decrypted_message, output_len);
    return unpadded_size;
}

/*************************************************
 *Name:        UAE_ReKeygen
 *
 *Description: Given AE_key1, AE_key2 and ciphertext_hat, generated delta, a token to 
 *             re_encrypt a ciphertext under AE_key2 instead of AE_key1.
 *
 *Arguments:   - int8_t *AE_key1: pointer to the first AE_key
 *             - int8_t *AE_key2: pointer to the second AE_key
 *             - UAE_lwe_ctx_header *ciphertext_hat: pointer to the ciphertext metadata
 *             - UAE_lwe_delta *delta: pointer to the delta token
 *
 *Returns:     0 if successful, -1 if not
 **************************************************/
int UAE_ReKeygen(int8_t *AE_key1, int8_t *AE_key2, UAE_lwe_ctx_header *ciphertext_hat, UAE_lwe_delta *delta)
{
    UAE_lwe_data_header data_header;

    int decrypted_ctx_header_length = gcm_decrypt(ciphertext_hat->ctx, sizeof(UAE_lwe_data_header),
        ciphertext_hat->tag,
        AE_key1,
        ciphertext_hat->iv, IV_LEN,
        (uint8_t*) &data_header);
    if (decrypted_ctx_header_length != sizeof(UAE_lwe_data_header))
    {
        printf("ERROR decrypting header\n");
        return -1;
    }

    poly_28 poly_key1, poly_key2;
    memcpy(&poly_key1, &data_header.poly_keya, sizeof(poly_28));
    memcpy(&poly_key2, &data_header.poly_keyb, sizeof(poly_28));
    lwe_gen_key(&data_header.poly_keya, &data_header.poly_keyb);

    for (int i = 0; i < NEWHOPE_N; i++) {
        delta->poly_keya.coeffs[i] = barrett_reduce_268369921(data_header.poly_keya.coeffs[i] - poly_key1.coeffs[i]);
        delta->poly_keyb.coeffs[i] = barrett_reduce_268361729(data_header.poly_keyb.coeffs[i] - poly_key2.coeffs[i]);
    }

    RAND_bytes(delta->ctx_header.iv, IV_LEN);
    int ctx_header_length = gcm_encrypt((uint8_t*) &data_header, sizeof(UAE_lwe_data_header),
        AE_key2,
        delta->ctx_header.iv, IV_LEN,
        delta->ctx_header.ctx,
        delta->ctx_header.tag);
    if (ctx_header_length != sizeof(UAE_lwe_data_header))
    {
        printf("ERROR encrypting header\n");
        return -1;
    }
    return 0;
}

/*************************************************
 *Name:        UAE_ReKeygen_avx
 *
 *Description: AVX form of UAE_ReKeygen.
 *             Given AE_key1, AE_key2 and ciphertext_hat, generated delta, a token to 
 *             re_encrypt a ciphertext under AE_key2 instead of AE_key1.
 *
 *Arguments:   - int8_t *AE_key1: pointer to the first AE_key
 *             - int8_t *AE_key2: pointer to the second AE_key
 *             - UAE_lwe_ctx_header *ciphertext_hat: pointer to the ciphertext metadata
 *             - UAE_lwe_delta *delta: pointer to the delta token
 *
 *Returns:     0 if successful, -1 if not
 **************************************************/
int UAE_ReKeygen_avx(int8_t *AE_key1, int8_t *AE_key2, UAE_lwe_ctx_header *ciphertext_hat, UAE_lwe_delta *delta)
{
    UAE_lwe_data_header data_header;

    int decrypted_ctx_header_length = gcm_decrypt(ciphertext_hat->ctx, sizeof(UAE_lwe_data_header),
        ciphertext_hat->tag,
        AE_key1,
        ciphertext_hat->iv, IV_LEN,
        (uint8_t*) &data_header);
    if (decrypted_ctx_header_length != sizeof(UAE_lwe_data_header))
    {
        printf("ERROR decrypting header\n");
        return -1;
    }

    poly_28 poly_key1, poly_key2;
    memcpy(&poly_key1, &data_header.poly_keya, sizeof(poly_28));
    memcpy(&poly_key2, &data_header.poly_keyb, sizeof(poly_28));
    lwe_gen_key_avx(&data_header.poly_keya, &data_header.poly_keyb);

    for (int i = 0; i < NEWHOPE_N; i++) {
        delta->poly_keya.coeffs[i] = barrett_reduce_268369921(data_header.poly_keya.coeffs[i] - poly_key1.coeffs[i]);
        delta->poly_keyb.coeffs[i] = barrett_reduce_268361729(data_header.poly_keyb.coeffs[i] - poly_key2.coeffs[i]);
    }

    RAND_bytes(delta->ctx_header.iv, IV_LEN);
    int ctx_header_length = gcm_encrypt((uint8_t*) &data_header, sizeof(UAE_lwe_data_header),
        AE_key2,
        delta->ctx_header.iv, IV_LEN,
        delta->ctx_header.ctx,
        delta->ctx_header.tag);
    if (ctx_header_length != sizeof(UAE_lwe_data_header))
    {
        printf("ERROR encrypting header\n");
        return -1;
    }
    return 0;
}

/*************************************************
 *Name:        UAE_ReEncrypt
 *
 *Description: Re_encrypts message using a delta token and outputs ciphertext_hat and ciphertext.
 *
 *Arguments:   - UAE_lwe_delta *delta: pointer to the delta token
 *             - UAE_lwe_ctx_header *ciphertext_hat1: pointer to the original ciphertext metadata.
 *             - uint8_t *ciphertext1: pointer to the original ciphertext
 *             - UAE_lwe_ctx_header *ciphertext_hat2: pointer to the generated ciphertext metadata.
 *             - uint8_t *ciphertext1: pointer to the generated ciphertext
 *             - unsigned int size: size of the message in bytes
 *
 *Returns:     The length of the re_encryped ciphertext in bytes.
 **************************************************/
int UAE_ReEncrypt(UAE_lwe_delta *delta,
    UAE_lwe_ctx_header *ciphertext_hat1, uint8_t *ciphertext1,
    UAE_lwe_ctx_header *ciphertext_hat2, uint8_t *ciphertext2, unsigned int size)
{

    memcpy(ciphertext_hat2, &delta->ctx_header, sizeof(UAE_lwe_ctx_header));

    int re_encrypt_length = kh_prf_re_encrypt_2_AB(&delta->poly_keya, &delta->poly_keyb, ciphertext1, ciphertext2, size);

    return re_encrypt_length;
}

/*************************************************
 *Name:        UAE_ReEncrypt_avx
 *
 *Description: AVX form of UAE_ReEncrypt.
 *             Re_encrypts message using a delta token and outputs ciphertext_hat and ciphertext.
 *
 *Arguments:   - UAE_lwe_delta *delta: pointer to the delta token
 *             - UAE_lwe_ctx_header *ciphertext_hat1: pointer to the original ciphertext metadata.
 *             - uint8_t *ciphertext1: pointer to the original ciphertext
 *             - UAE_lwe_ctx_header *ciphertext_hat2: pointer to the generated ciphertext metadata.
 *             - uint8_t *ciphertext1: pointer to the generated ciphertext
 *             - unsigned int size: size of the message in bytes
 *
 *Returns:     The length of the re_encryped ciphertext in bytes.
 **************************************************/
int UAE_ReEncrypt_avx(UAE_lwe_delta *delta,
    UAE_lwe_ctx_header *ciphertext_hat1, uint8_t *ciphertext1,
    UAE_lwe_ctx_header *ciphertext_hat2, uint8_t *ciphertext2, unsigned int size)
{

    memcpy(ciphertext_hat2, &delta->ctx_header, sizeof(UAE_lwe_ctx_header));

    int re_encrypt_length = kh_prf_re_encrypt_2_AB_avx(&delta->poly_keya, &delta->poly_keyb, ciphertext1, ciphertext2, size);

    return re_encrypt_length;
}