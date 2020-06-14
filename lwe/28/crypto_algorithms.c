#include "crypto_algorithms.h"
#include <openssl/rand.h>
#include "fips202.h"
#include "fips202x4.h"

/*************************************************
 *Name:        mult_poly_ntru
 *
 *Description: This should ONLY be used in testing. Runs slowly but is correct.
 *
 *Arguments:   - poly_28 *result: pointer to the product
 *             - poly_28 *poly_a: pointer to the first poly_28 input
 *             - poly_28 *poly_b: pointer to the second poly_28 input
 *
 *Returns:     None
 **************************************************/
void mult_poly_ntru(poly_28 *result, poly_28 *poly_a, poly_28 *poly_b)
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
            int64_t tmp = ((int64_t) poly_a->coeffs[(i)] *poly_b->coeffs[j]) % (int64_t) Q;

            if (((i + j) / NEWHOPE_N) % 2 == 1) tmp = -tmp;

            result->coeffs[deg] = ((int64_t) tmp + (int64_t) result->coeffs[deg]) % (int64_t) Q;
        }
    }
}

/*************************************************
 *Name:        poly_uniform_ref_poly_28
 *
 *Description: Takes in a 32 bytes seed, generates a poly_28 with shake128 
 *             uniformly random elements in mod Q.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_28 *a: pointer to the poly_28 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_poly_28(poly_28 *a, const unsigned char *seed)
{
    unsigned int ctr = 0;
    uint32_t val;
    uint64_t state[25];
    uint8_t buf[SHAKE128_RATE];
    uint8_t extseed[(NEWHOPE_SYMBYTES + 2)];
    int i, j;

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

        shake128_absorb(state, extseed, NEWHOPE_SYMBYTES + 1);
        shake128_squeezeblocks(buf, 1, state);

        for (j = 0; j < SHAKE128_RATE - SAMPLE_BLOCK_SIZE && coeffs_written < NEWHOPE_N; j += 7)
        {
            uint32_t sample_1 = ((uint32_t) buf[j] | ((uint32_t) buf[j + 1] << 8) | ((uint32_t) buf[j + 2] << 16) | ((uint32_t)(buf[j + 3] &15) << 24));

            if (sample_1 < Q)
            {
                a->coeffs[coeffs_written] = sample_1;
                coeffs_written++;
            }

            if (coeffs_written == NEWHOPE_N) break;

            uint32_t sample_2 = ((uint32_t) buf[j + 4] | ((uint32_t) buf[j + 5] << 8) | ((uint32_t) buf[j + 6] << 16) | ((uint32_t)(buf[j + 3] &240) << 20));
            if (sample_2 < Q)
            {
                a->coeffs[coeffs_written] = sample_2;
                coeffs_written++;
            }
        }

        iteration++;
    }
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
 *Name:        poly_uniform_ref_poly_28_avx
 *
 *Description: AVX2 form of poly_uniform_ref_poly_28_avx.
 *             Takes in a 32 bytes seed, generates a poly_28 with shake128 
 *             uniformly random elements in mod Q.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_28 *a: pointer to the poly_28 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_poly_28_avx(poly_28 *a, const unsigned char *seed)
{
    uint8_t buf[4 *SHAKE128_RATE];
    uint8_t extseed0[NEWHOPE_SYMBYTES + 2];
    uint8_t extseed1[NEWHOPE_SYMBYTES + 2];
    uint8_t extseed2[NEWHOPE_SYMBYTES + 2];
    uint8_t extseed3[NEWHOPE_SYMBYTES + 2];
    int i, j;

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
                uint32_t sample_1 = ((uint32_t) buf[j + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 1 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 2 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &15) << 24));

                if (sample_1 < Q)
                {
                    a->coeffs[coeffs_written] = sample_1;
                    coeffs_written++;
                }

                if (coeffs_written == NEWHOPE_N) break;

                uint32_t sample_2 = ((uint32_t) buf[j + 4 + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 5 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 6 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &240) << 20));

                if (sample_2 < Q)
                {
                    a->coeffs[coeffs_written] = sample_1;
                    coeffs_written++;
                }
            }
        }

        iteration++;
    }
}

/*************************************************
 *Name:        poly_uniform_ref_noise_12_2_seeds_pseudo
 *
 *Description: Takes in a 32 bytes seed, generates a poly_28 with shake128 
 *             uniformly random elements in mod Q. Differs than poly_uniform_ref_poly_28
 *             because it is used to generate the noise poly so the input extseed is different.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_28 *a: pointer to the poly_28 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_noise_12_2_seeds_pseudo(poly_28 *a, const unsigned char *seed)
{
    unsigned int ctr = 0;
    uint32_t val;
    uint64_t state[25];
    uint8_t buf[SHAKE128_RATE];
    uint8_t extseed[(2 *NEWHOPE_SYMBYTES + 2)];
    int i, j;

    for (i = 0; i < 2 *NEWHOPE_SYMBYTES + 2; i++) extseed[i] = 0;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        extseed[i] = seed[i];

    int coeffs_written = 0;
    int iteration = 0;
    uint8_t *a_byte = (int8_t*) a;

    while (coeffs_written != NEWHOPE_N)
    {
        if (iteration == 65536) printf("ERROR: poly_uniform_ref_poly_28: iteration hit its limit\n");
        for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        {
            extseed[i + NEWHOPE_SYMBYTES] += 1;
            if (extseed[i + NEWHOPE_SYMBYTES] != 0) break;
        }

        extseed[2 *NEWHOPE_SYMBYTES] = iteration; /*domain-separate the 16 independent calls */

        if (extseed[2 *NEWHOPE_SYMBYTES + 1] == 0) extseed[NEWHOPE_SYMBYTES + 1]++;

        shake128_absorb(state, extseed, NEWHOPE_SYMBYTES + 1);
        shake128_squeezeblocks(buf, 1, state);

        for (j = 0; j < SHAKE128_RATE - 3 && coeffs_written < NEWHOPE_N; j += 3)
        {
            uint32_t sample_1 = ((uint32_t) buf[j] | ((uint32_t)(buf[j + 1] &15) << 8));

            if (sample_1 < NOISE_MULT_MAX)
            {
                a->coeffs[coeffs_written] = sample_1 / NOISE_MAX_FACTOR;
                coeffs_written++;
            }

            if (coeffs_written == NEWHOPE_N) break;

            uint32_t sample_2 = ((uint32_t) buf[j + 2] | ((uint32_t)(buf[j + 1] &240) << 4));

            if (sample_2 < NOISE_MULT_MAX)
            {
                a->coeffs[coeffs_written] = sample_2 / NOISE_MAX_FACTOR;
                coeffs_written++;
            }
        }

        iteration++;
    }
}

/*************************************************
 *Name:        poly_uniform_ref_noise_12_2_seeds_pseudo_avx
 *
 *Description: AVX2 version of poly_uniform_ref_noise_12_2_seeds_pseudo.
 *             Takes in a 32 bytes seed, generates a poly_28 with shake128 
 *             uniformly random elements in mod Q. Differs than poly_uniform_ref_poly_28
 *             because it is used to generate the noise poly so the input extseed is different.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_28 *a: pointer to the poly_28 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_noise_12_2_seeds_pseudo_avx(poly_28 *a, const unsigned char *seed)
{
    uint8_t buf[4 *SHAKE128_RATE];
    uint8_t extseed0[2 *NEWHOPE_SYMBYTES + 2];
    uint8_t extseed1[2 *NEWHOPE_SYMBYTES + 2];
    uint8_t extseed2[2 *NEWHOPE_SYMBYTES + 2];
    uint8_t extseed3[2 *NEWHOPE_SYMBYTES + 2];
    int i, j;

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
            for (j = 0; j < SHAKE128_RATE - 3 && coeffs_written < NEWHOPE_N; j += 3)
            {
                uint32_t sample_1 = ((uint32_t) buf[j + i *SHAKE128_RATE] | ((uint32_t)(buf[j + 1 + i *SHAKE128_RATE] &15) << 8));

                if (sample_1 < NOISE_MULT_MAX)
                {
                    a->coeffs[coeffs_written] = sample_1 / NOISE_MAX_FACTOR;
                    coeffs_written++;
                }

                if (coeffs_written == NEWHOPE_N) break;

                uint32_t sample_2 = ((uint32_t) buf[j + 2 + i *SHAKE128_RATE] | ((uint32_t)(buf[j + 1 + i *SHAKE128_RATE] &240) << 4));

                if (sample_2 < NOISE_MULT_MAX)
                {
                    a->coeffs[coeffs_written] = sample_2 / NOISE_MAX_FACTOR;
                    coeffs_written++;
                }
            }
        }

        iteration++;
    }
}

/*************************************************
 *Name:        create_product_point
 *
 *Description: Takes in a poly_28 key_point_poly and seed of a poly_28, point_seed,
 *             generated the second poly_28 from point_seed, multiplies then as if they
 *             they are in the NTT domain, then computes the inverse NTT of the product.
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the poly_28 input
 *             - poly_28 *product_point_poly: pointer to the poly_28 product
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void create_product_point(poly_28 *key_point_poly, poly_28 *product_point_poly, unsigned char *point_seed)
{
    int i;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        point_seed[i] += 1;
        if (point_seed[i] != 0) break;
    }

    poly_28 point_poly;

    poly_uniform_ref_poly_28(&point_poly, point_seed);

    poly_basemul(product_point_poly, key_point_poly, &point_poly);
    poly_invntt(product_point_poly);
}

/*************************************************
 *Name:        create_product_point
 *
 *Description: AVX2 version of create_product_point.
 *             Takes in a poly_28 key_point_poly and seed of a poly_28, point_seed,
 *             generated the second poly_28 from point_seed, multiplies then as if they
 *             they are in the NTT domain, then computes the inverse NTT of the product.
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the poly_28 input
 *             - poly_28 *product_point_poly: pointer to the poly_28 product
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void create_product_point_avx(poly_28 *key_point_poly, poly_28 *product_point_poly, unsigned char *point_seed)
{
    int i;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        point_seed[i] += 1;
        if (point_seed[i] != 0) break;
    }

    poly_28 point_poly;

    poly_uniform_ref_poly_28_avx(&point_poly, point_seed);

    poly_basemul(product_point_poly, key_point_poly, &point_poly);
    poly_invntt_avx(product_point_poly);
}

/*************************************************
 *Name:        lwe_gen_key
 *
 *Description: Generated a random poly_28 with no input.
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the poly_28 generated
 *
 *Returns:     None
 **************************************************/
void lwe_gen_key(poly_28 *key_point_poly)
{
    uint8_t key_seed[NEWHOPE_SYMBYTES];
    RAND_bytes(key_seed, NEWHOPE_SYMBYTES);
    poly_uniform_ref_poly_28(key_point_poly, key_seed);
}

void lwe_gen_key_avx(poly_28 *key_point_poly)
{
    uint8_t key_seed[NEWHOPE_SYMBYTES];
    RAND_bytes(key_seed, NEWHOPE_SYMBYTES);
    poly_uniform_ref_poly_28_avx(key_point_poly, key_seed);
}

/*************************************************
 *Name:        kh_prf_encrypt
 *
 *Description: KH_PRF to encrypt buf using key_point_poly.
 *             Assumes that the message has been padded to be a multiple of seven
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the poly_28 key
 *             - uint8_t *buf: pointer to the message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     None
 **************************************************/
void kh_prf_encrypt(poly_28 *key_point_poly, uint8_t *buf, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_28 product_poly;
    poly_28 noise_poly;

    uint32_t guassian_output;

    int bytes_processed = 0;
    while (bytes_processed < size)
    {
        create_product_point(key_point_poly, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_12_2_seeds_pseudo(&noise_poly, (unsigned char *) &key_point_poly);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {
            uint32_t sample_1 = ((uint32_t) buf[bytes_processed] |
                ((uint32_t) buf[bytes_processed + 1] << 8) |
                ((uint32_t) buf[bytes_processed + 2] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &15) << 24));
            uint32_t sample_2 = ((uint32_t) buf[bytes_processed + 4] |
                ((uint32_t) buf[bytes_processed + 5] << 8) |
                ((uint32_t) buf[bytes_processed + 6] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &240) << 20));

            sample_1 = barrett_reduce(sample_1 + (uint32_t) product_poly.coeffs[i] + (uint32_t) noise_poly.coeffs[i] - NOISE_MAX / 2);
            sample_2 = barrett_reduce(sample_2 + (uint32_t) product_poly.coeffs[i + 1] + (uint32_t) noise_poly.coeffs[i + 1] - NOISE_MAX / 2);

            buf[bytes_processed] = sample_1 &255;
            buf[bytes_processed + 1] = (sample_1 &(255 << 8)) >> 8;
            buf[bytes_processed + 2] = (sample_1 &(255 << 16)) >> 16;
            buf[bytes_processed + 3] = (sample_1 &(15 << 24)) >> 24;

            buf[bytes_processed + 4] = sample_2 &255;
            buf[bytes_processed + 5] = (sample_2 &(255 << 8)) >> 8;
            buf[bytes_processed + 6] = (sample_2 &(255 << 16)) >> 16;
            buf[bytes_processed + 3] |= (sample_2 &(15 << 24)) >> 20;

            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
}

/*************************************************
 *Name:        kh_prf_encrypt_2
 *
 *Description: KH_PRF to encrypt buf using key_point_poly. Similar to kh_prf_encrypt
 *             but the bottom 2 bytes of each coefficient is empty.
 *             Assumes that the message has been padded to be a multiple of three.
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the poly_28 key
 *             - uint8_t *buf: pointer to the message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     None
 **************************************************/
int kh_prf_encrypt_2(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_28 product_poly;
    poly_28 noise_poly;

    uint32_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;
    while (bytes_processed < size)
    {
        create_product_point(key_point_poly, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_12_2_seeds_pseudo(&noise_poly, (unsigned char *) &key_point_poly);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {
            uint32_t sample_1 = ((uint32_t) NOISE_MAX |
                ((uint32_t) buf[bytes_processed] << 16) |
                ((uint32_t)(buf[bytes_processed + 1] &15) << 24));
            uint32_t sample_2 = ((uint32_t) NOISE_MAX |
                ((uint32_t) buf[bytes_processed + 2] << 16) |
                ((uint32_t)(buf[bytes_processed + 1] &240) << 20));

            sample_1 = barrett_reduce(sample_1 + (uint32_t) product_poly.coeffs[i] + (uint32_t) noise_poly.coeffs[i]);
            sample_2 = barrett_reduce(sample_2 + (uint32_t) product_poly.coeffs[i + 1] + (uint32_t) noise_poly.coeffs[i + 1]);

            out[bytes_written] = sample_1 &255;
            out[bytes_written + 1] = (sample_1 &(255 << 8)) >> 8;
            out[bytes_written + 2] = (sample_1 &(255 << 16)) >> 16;
            out[bytes_written + 3] = (sample_1 &(15 << 24)) >> 24;

            out[bytes_written + 4] = sample_2 &255;
            out[bytes_written + 5] = (sample_2 &(255 << 8)) >> 8;
            out[bytes_written + 6] = (sample_2 &(255 << 16)) >> 16;
            out[bytes_written + 3] |= (sample_2 &(15 << 24)) >> 20;

            bytes_processed += PAD_SIZE;
            bytes_written += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_encrypt_avx
 *
 *Description: AVX2 version of kh_prf_encrypt.
 *             KH_PRF to encrypt buf using key_point_poly.
 *             Assumes that the message has been padded to be a multiple of seven
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the poly_28 key
 *             - uint8_t *buf: pointer to the message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     None
 **************************************************/
void kh_prf_encrypt_avx(poly_28 *key_point_poly, uint8_t *buf, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_28 product_poly;
    poly_28 noise_poly;

    uint32_t guassian_output;

    int bytes_processed = 0;
    while (bytes_processed < size)
    {
        create_product_point_avx(key_point_poly, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_12_2_seeds_pseudo_avx(&noise_poly, (unsigned char *) &key_point_poly);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {
            uint32_t sample_1 = ((uint32_t) buf[bytes_processed] |
                ((uint32_t) buf[bytes_processed + 1] << 8) |
                ((uint32_t) buf[bytes_processed + 2] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &15) << 24));
            uint32_t sample_2 = ((uint32_t) buf[bytes_processed + 4] |
                ((uint32_t) buf[bytes_processed + 5] << 8) |
                ((uint32_t) buf[bytes_processed + 6] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &240) << 20));

            sample_1 = barrett_reduce(sample_1 + (uint32_t) product_poly.coeffs[i] + (uint32_t) noise_poly.coeffs[i] - NOISE_MAX / 2);
            sample_2 = barrett_reduce(sample_2 + (uint32_t) product_poly.coeffs[i + 1] + (uint32_t) noise_poly.coeffs[i + 1] - NOISE_MAX / 2);

            buf[bytes_processed] = sample_1 &255;
            buf[bytes_processed + 1] = (sample_1 &(255 << 8)) >> 8;
            buf[bytes_processed + 2] = (sample_1 &(255 << 16)) >> 16;
            buf[bytes_processed + 3] = (sample_1 &(15 << 24)) >> 24;

            buf[bytes_processed + 4] = sample_2 &255;
            buf[bytes_processed + 5] = (sample_2 &(255 << 8)) >> 8;
            buf[bytes_processed + 6] = (sample_2 &(255 << 16)) >> 16;
            buf[bytes_processed + 3] |= (sample_2 &(15 << 24)) >> 20;

            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
}

/*************************************************
 *Name:        kh_prf_encrypt_2_avx
 *
 *Description: AVX2 version of kh_prf_encrypt_2.
 *             KH_PRF to encrypt buf using key_point_poly. Similar to kh_prf_encrypt
 *             but the bottom 2 bytes of each coefficient is empty.
 *             Assumes that the message has been padded to be a multiple of three.
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the poly_28 key
 *             - uint8_t *buf: pointer to the message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_encrypt_2_avx(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_28 product_poly;
    poly_28 noise_poly;

    uint32_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;
    while (bytes_processed < size)
    {
        create_product_point_avx(key_point_poly, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_12_2_seeds_pseudo_avx(&noise_poly, (unsigned char *) &key_point_poly);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {
            uint32_t sample_1 = ((uint32_t) NOISE_MAX |
                ((uint32_t) buf[bytes_processed] << 16) |
                ((uint32_t)(buf[bytes_processed + 1] &15) << 24));
            uint32_t sample_2 = ((uint32_t) NOISE_MAX |
                ((uint32_t) buf[bytes_processed + 2] << 16) |
                ((uint32_t)(buf[bytes_processed + 1] &240) << 20));

            sample_1 = barrett_reduce(sample_1 + (uint32_t) product_poly.coeffs[i] + (uint32_t) noise_poly.coeffs[i]);
            sample_2 = barrett_reduce(sample_2 + (uint32_t) product_poly.coeffs[i + 1] + (uint32_t) noise_poly.coeffs[i + 1]);

            out[bytes_written] = sample_1 &255;
            out[bytes_written + 1] = (sample_1 &(255 << 8)) >> 8;
            out[bytes_written + 2] = (sample_1 &(255 << 16)) >> 16;
            out[bytes_written + 3] = (sample_1 &(15 << 24)) >> 24;

            out[bytes_written + 4] = sample_2 &255;
            out[bytes_written + 5] = (sample_2 &(255 << 8)) >> 8;
            out[bytes_written + 6] = (sample_2 &(255 << 16)) >> 16;
            out[bytes_written + 3] |= (sample_2 &(15 << 24)) >> 20;

            bytes_processed += PAD_SIZE;
            bytes_written += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_decrypt_2
 *
 *Description: KH_PRF to decrypt buf using key_point_poly. Similar to kh_prf_decrypt
 *             but the bottom 2 bytes of each coefficient is empty.
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the poly_28 key
 *             - uint8_t *buf: pointer to the ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     The length of the decrypted message in bytes.
 **************************************************/
int kh_prf_decrypt_2(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_28 product_poly;

    uint32_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;
    while (bytes_processed < size)
    {
        create_product_point(key_point_poly, &product_poly, (unsigned char *) &point_seed);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {
            uint32_t sample_1 = ((uint32_t) buf[bytes_processed] |
                ((uint32_t) buf[bytes_processed + 1] << 8) |
                ((uint32_t) buf[bytes_processed + 2] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &15) << 24));
            uint32_t sample_2 = ((uint32_t) buf[bytes_processed + 4] |
                ((uint32_t) buf[bytes_processed + 5] << 8) |
                ((uint32_t) buf[bytes_processed + 6] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &240) << 20));

            sample_1 = barrett_reduce(sample_1 - (uint32_t) product_poly.coeffs[i]);
            sample_2 = barrett_reduce(sample_2 - (uint32_t) product_poly.coeffs[i + 1]);

            out[bytes_written] = (sample_1 &(255 << 16)) >> 16;
            out[bytes_written + 1] = (sample_1 &(15 << 24)) >> 24;

            out[bytes_written + 2] = (sample_2 &(255 << 16)) >> 16;
            out[bytes_written + 1] |= (sample_2 &(15 << 24)) >> 20;

            bytes_processed += SAMPLE_BLOCK_SIZE;
            bytes_written += PAD_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_decrypt_2_avx
 *
 *Description: AVX2 version of kh_prf_decrypt_2.
 *             KH_PRF to decrypt buf using key_point_poly. Similar to kh_prf_decrypt
 *             but the bottom 2 bytes of each coefficient is empty.
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the poly_28 key
 *             - uint8_t *buf: pointer to the ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     The length of the decrypted message in bytes.
 **************************************************/
int kh_prf_decrypt_2_avx(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_28 product_poly;

    uint32_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;
    while (bytes_processed < size)
    {
        create_product_point_avx(key_point_poly, &product_poly, (unsigned char *) &point_seed);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {
            uint32_t sample_1 = ((uint32_t) buf[bytes_processed] |
                ((uint32_t) buf[bytes_processed + 1] << 8) |
                ((uint32_t) buf[bytes_processed + 2] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &15) << 24));
            uint32_t sample_2 = ((uint32_t) buf[bytes_processed + 4] |
                ((uint32_t) buf[bytes_processed + 5] << 8) |
                ((uint32_t) buf[bytes_processed + 6] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &240) << 20));

            sample_1 = barrett_reduce(sample_1 - (uint32_t) product_poly.coeffs[i]);
            sample_2 = barrett_reduce(sample_2 - (uint32_t) product_poly.coeffs[i + 1]);

            out[bytes_written] = (sample_1 &(255 << 16)) >> 16;
            out[bytes_written + 1] = (sample_1 &(15 << 24)) >> 24;

            out[bytes_written + 2] = (sample_2 &(255 << 16)) >> 16;
            out[bytes_written + 1] |= (sample_2 &(15 << 24)) >> 20;

            bytes_processed += SAMPLE_BLOCK_SIZE;
            bytes_written += PAD_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_re_encrypt
 *
 *Description: KH_PRF to re_encrypt buf using key_point_poly_2.
 *
 *Arguments:   - poly_28 *key_point_poly_1: pointer to the original poly_28 key
 *             - poly_28 *key_point_poly_2: pointer to the new poly_28 key
 *             - uint8_t *test_array: pointer to the ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     None
 **************************************************/
void kh_prf_re_encrypt(poly_28 *key_point_poly_1, poly_28 *key_point_poly_2, uint8_t *test_array, unsigned int size)
{
    poly_28 diff_poly;

    for (int i = 0; i < NEWHOPE_N; i++) diff_poly.coeffs[i] = barrett_reduce(key_point_poly_2->coeffs[i] - key_point_poly_1->coeffs[i]);

    kh_prf_encrypt(&diff_poly, test_array, size);
}

/*************************************************
 *Name:        kh_prf_re_encrypt_avx
 *
 *Description: AVX2 version of kh_prf_re_encrypt. 
 *             KH_PRF to re_encrypt buf using key_point_poly_2.
 *
 *Arguments:   - poly_28 *key_point_poly_1: pointer to the original poly_28 key
 *             - poly_28 *key_point_poly_2: pointer to the new poly_28 key
 *             - uint8_t *test_array: pointer to the ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     None
 **************************************************/
void kh_prf_re_encrypt_avx(poly_28 *key_point_poly_1, poly_28 *key_point_poly_2, uint8_t *test_array, unsigned int size)
{
    poly_28 diff_poly;

    for (int i = 0; i < NEWHOPE_N; i++) diff_poly.coeffs[i] = barrett_reduce(key_point_poly_2->coeffs[i] - key_point_poly_1->coeffs[i]);

    kh_prf_encrypt_avx(&diff_poly, test_array, size);
}

/*************************************************
 *Name:        kh_prf_re_encrypt_2
 *
 *Description: KH_PRF to re_encrypt buf using key_point_poly. Simliar to
 *             kh_prf_re_encrypt but set eh the bottom 2 bytes of each coefficient
 *             to be empty.
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the delta of the new and old key
 *             - uint8_t *buf: pointer to the input ciphertext
 *             - uint8_t *output: pointer to the output ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_re_encrypt_2(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_28 product_poly;
    poly_28 noise_poly;

    uint32_t guassian_output;

    int bytes_processed = 0;

    while (bytes_processed < size)
    {
        create_product_point(key_point_poly, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_12_2_seeds_pseudo(&noise_poly, (unsigned char *) &key_point_poly);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {
            uint32_t sample_1 = ((uint32_t) buf[bytes_processed] |
                ((uint32_t) buf[bytes_processed + 1] << 8) |
                ((uint32_t) buf[bytes_processed + 2] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &15) << 24));
            uint32_t sample_2 = ((uint32_t) buf[bytes_processed + 4] |
                ((uint32_t) buf[bytes_processed + 5] << 8) |
                ((uint32_t) buf[bytes_processed + 6] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &240) << 20));

            sample_1 = barrett_reduce(sample_1 + (uint32_t) product_poly.coeffs[i] + (uint32_t) noise_poly.coeffs[i]);
            sample_2 = barrett_reduce(sample_2 + (uint32_t) product_poly.coeffs[i + 1] + (uint32_t) noise_poly.coeffs[i + 1]);

            out[bytes_processed] = sample_1 &255;
            out[bytes_processed + 1] = (sample_1 &(255 << 8)) >> 8;
            out[bytes_processed + 2] = (sample_1 &(255 << 16)) >> 16;
            out[bytes_processed + 3] = (sample_1 &(15 << 24)) >> 24;

            out[bytes_processed + 4] = sample_2 &255;
            out[bytes_processed + 5] = (sample_2 &(255 << 8)) >> 8;
            out[bytes_processed + 6] = (sample_2 &(255 << 16)) >> 16;
            out[bytes_processed + 3] |= (sample_2 &(15 << 24)) >> 20;

            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_processed;
}

/*************************************************
 *Name:        kh_prf_re_encrypt_2_avx
 *
 *Description: AVX2 version of kh_prf_re_encrypt_2.
 *             KH_PRF to re_encrypt buf using key_point_poly. Simliar to
 *             kh_prf_re_encrypt but set eh the bottom 2 bytes of each coefficient
 *             to be empty..
 *
 *Arguments:   - poly_28 *key_point_poly: pointer to the delta of the new and old key
 *             - uint8_t *buf: pointer to the input ciphertext
 *             - uint8_t *output: pointer to the output ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_re_encrypt_2_avx(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_28 product_poly;
    poly_28 noise_poly;

    uint32_t guassian_output;

    int bytes_processed = 0;

    while (bytes_processed < size)
    {
        create_product_point_avx(key_point_poly, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_12_2_seeds_pseudo_avx(&noise_poly, (unsigned char *) &key_point_poly);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {
            uint32_t sample_1 = ((uint32_t) buf[bytes_processed] |
                ((uint32_t) buf[bytes_processed + 1] << 8) |
                ((uint32_t) buf[bytes_processed + 2] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &15) << 24));
            uint32_t sample_2 = ((uint32_t) buf[bytes_processed + 4] |
                ((uint32_t) buf[bytes_processed + 5] << 8) |
                ((uint32_t) buf[bytes_processed + 6] << 16) |
                ((uint32_t)(buf[bytes_processed + 3] &240) << 20));

            sample_1 = barrett_reduce(sample_1 + (uint32_t) product_poly.coeffs[i] + (uint32_t) noise_poly.coeffs[i]);
            sample_2 = barrett_reduce(sample_2 + (uint32_t) product_poly.coeffs[i + 1] + (uint32_t) noise_poly.coeffs[i + 1]);

            out[bytes_processed] = sample_1 &255;
            out[bytes_processed + 1] = (sample_1 &(255 << 8)) >> 8;
            out[bytes_processed + 2] = (sample_1 &(255 << 16)) >> 16;
            out[bytes_processed + 3] = (sample_1 &(15 << 24)) >> 24;

            out[bytes_processed + 4] = sample_2 &255;
            out[bytes_processed + 5] = (sample_2 &(255 << 8)) >> 8;
            out[bytes_processed + 6] = (sample_2 &(255 << 16)) >> 16;
            out[bytes_processed + 3] |= (sample_2 &(15 << 24)) >> 20;

            bytes_processed += 7;
        }
    }
    return bytes_processed;
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
    lwe_gen_key(&data_header.poly_key);

    int padded_size = pad_array(message, size);

    poly_uniform_ref_message(data_header.hash, message, padded_size);
    RAND_bytes(ciphertext_hat->iv, IV_LEN);
    int ctx_header_length = gcm_encrypt((uint8_t*) &data_header, sizeof(UAE_lwe_data_header),
        AE_key,
        ciphertext_hat->iv, IV_LEN,
        ciphertext_hat->ctx,
        ciphertext_hat->tag);

    int output_len = kh_prf_encrypt_2(&data_header.poly_key, message, ciphertext, padded_size);

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

    int output_len = kh_prf_decrypt_2(&data_header.poly_key, ciphertext, decrypted_message, size);
    uint8_t hash[SHAKE128_RATE];
    poly_uniform_ref_message(hash, decrypted_message, output_len);

    for (int i = 0; i < SHAKE128_RATE; i++)
    {
        if (data_header.hash[i] != hash[i])
        {
            printf("HASH DOES NOT MATCH\n");
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

    poly_28 poly_key1;
    memcpy(&poly_key1, &data_header.poly_key, sizeof(poly_28));
    lwe_gen_key(&data_header.poly_key);

    for (int i = 0; i < NEWHOPE_N; i++) delta->poly_key.coeffs[i] = barrett_reduce(data_header.poly_key.coeffs[i] - poly_key1.coeffs[i]);

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

    poly_28 poly_key1;
    memcpy(&poly_key1, &data_header.poly_key, sizeof(poly_28));
    lwe_gen_key_avx(&data_header.poly_key);

    for (int i = 0; i < NEWHOPE_N; i++) delta->poly_key.coeffs[i] = barrett_reduce(data_header.poly_key.coeffs[i] - poly_key1.coeffs[i]);

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

    int re_encrypt_length = kh_prf_re_encrypt_2(&delta->poly_key, ciphertext1, ciphertext2, size);

    return re_encrypt_length;
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
    lwe_gen_key_avx(&data_header.poly_key);

    int padded_size = pad_array(message, size);

    poly_uniform_ref_message(data_header.hash, message, padded_size);
    RAND_bytes(ciphertext_hat->iv, IV_LEN);
    int ctx_header_length = gcm_encrypt((uint8_t*) &data_header, sizeof(UAE_lwe_data_header),
        AE_key,
        ciphertext_hat->iv, IV_LEN,
        ciphertext_hat->ctx,
        ciphertext_hat->tag);

    int output_len = kh_prf_encrypt_2_avx(&data_header.poly_key, message, ciphertext, padded_size);

    return output_len;
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

    int output_len = kh_prf_decrypt_2_avx(&data_header.poly_key, ciphertext, decrypted_message, size);
    uint8_t hash[SHAKE128_RATE];
    poly_uniform_ref_message(hash, decrypted_message, output_len);

    for (int i = 0; i < SHAKE128_RATE; i++)
    {
        if (data_header.hash[i] != hash[i])
        {
            printf("HASH DOES NOT MATCH\n");
            return -1;
        }
    }

    int unpadded_size = unpad_array(decrypted_message, output_len);
    return unpadded_size;
}

/*************************************************
 *Name:        UAE_ReEncrypt_avx
 *
 *Description: AVX2 version of UAE_ReEncrypt. Re_encrypts message using a delta token and outputs ciphertext_hat and ciphertext.
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
    int re_encrypt_length = kh_prf_re_encrypt_2_avx(&delta->poly_key, ciphertext1, ciphertext2, size);

    return re_encrypt_length;
}