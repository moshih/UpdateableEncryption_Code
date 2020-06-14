#include "crypto_algorithms.h"

/*************************************************
*Name:        montgomery_reduce_AB
*
*Description: Montgomery reduction; given a 128-bit integer a, computes
*             64-bit integer congruent to a *R^-1 mod Q_AB,
*             where R=2^64
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
 *Name:        poly_uniform_ref_poly_28_ABC
 *
 *Description: Takes in a 32 bytes seed, generates 3 poly_28 with shake128 
 *             uniformly random elements in mod QA, QB, or QC.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_28 *a: pointer to the poly_28 to be generated mod QA
 *             - poly_28 *b: pointer to the poly_28 to be generated mod QB
 *             - poly_28 *c: pointer to the poly_28 to be generated mod QC
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_poly_28_ABC(poly_28 *a, poly_28 *b, poly_28 *c, const unsigned char *seed)
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

        shake128_absorb(state, extseed, NEWHOPE_SYMBYTES + 2);
        shake128_squeezeblocks(buf, 1, state);

        for (j = 0; j < SHAKE128_RATE - SAMPLE_BLOCK_SIZE && coeffs_written < NEWHOPE_N; j += 7)
        {
            uint32_t sample_1 = ((uint32_t) buf[j] | ((uint32_t) buf[j + 1] << 8) | ((uint32_t) buf[j + 2] << 16) | ((uint32_t)(buf[j + 3] &15) << 24));

            if (sample_1 < QA)
            {
                a->coeffs[coeffs_written] = sample_1;
                coeffs_written++;
            }

            if (coeffs_written == NEWHOPE_N) break;

            uint32_t sample_2 = ((uint32_t) buf[j + 4] | ((uint32_t) buf[j + 5] << 8) | ((uint32_t) buf[j + 6] << 16) | ((uint32_t)(buf[j + 3] &240) << 20));
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
            uint32_t sample_1 = ((uint32_t) buf[j] | ((uint32_t) buf[j + 1] << 8) | ((uint32_t) buf[j + 2] << 16) | ((uint32_t)(buf[j + 3] &15) << 24));

            if (sample_1 < QB)
            {
                b->coeffs[coeffs_written] = sample_1;
                coeffs_written++;
            }

            if (coeffs_written == NEWHOPE_N) break;

            uint32_t sample_2 = ((uint32_t) buf[j + 4] | ((uint32_t) buf[j + 5] << 8) | ((uint32_t) buf[j + 6] << 16) | ((uint32_t)(buf[j + 3] &240) << 20));
            if (sample_2 < QB)
            {
                b->coeffs[coeffs_written] = sample_2;
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
            uint32_t sample_1 = ((uint32_t) buf[j] | ((uint32_t) buf[j + 1] << 8) | ((uint32_t) buf[j + 2] << 16) | ((uint32_t)(buf[j + 3] &15) << 24));

            if (sample_1 < QC)
            {
                c->coeffs[coeffs_written] = sample_1;
                coeffs_written++;
            }

            if (coeffs_written == NEWHOPE_N) break;

            uint32_t sample_2 = ((uint32_t) buf[j + 4] | ((uint32_t) buf[j + 5] << 8) | ((uint32_t) buf[j + 6] << 16) | ((uint32_t)(buf[j + 3] &240) << 20));
            if (sample_2 < QC)
            {
                c->coeffs[coeffs_written] = sample_2;
                coeffs_written++;
            }
        }

        iteration++;
    }
}

/*************************************************
 *Name:        poly_uniform_ref_poly_28_ABC_avx
 *
 *Description: AVX2 form of poly_uniform_ref_poly_28_ABC.
 *             Takes in a 32 bytes seed, generates a poly_28 with shake128 
 *             uniformly random elements in mod Q.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_28 *a: pointer to the poly_28 to be generated mod QA
 *             - poly_28 *b: pointer to the poly_28 to be generated mod QB
 *             - poly_28 *c: pointer to the poly_28 to be generated mod QC
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_poly_28_ABC_avx(poly_28 *a, poly_28 *b, poly_28 *c, const unsigned char *seed)
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

                if (sample_1 < QA)
                {
                    a->coeffs[coeffs_written] = sample_1;
                    coeffs_written++;
                }

                if (coeffs_written == NEWHOPE_N) break;

                uint32_t sample_2 = ((uint32_t) buf[j + 4 + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 5 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 6 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &240) << 20));

                if (sample_2 < QA)
                {
                    a->coeffs[coeffs_written] = sample_1;
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
                uint32_t sample_1 = ((uint32_t) buf[j + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 1 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 2 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &15) << 24));

                if (sample_1 < QB)
                {
                    b->coeffs[coeffs_written] = sample_1;
                    coeffs_written++;
                }

                if (coeffs_written == NEWHOPE_N) break;

                uint32_t sample_2 = ((uint32_t) buf[j + 4 + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 5 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 6 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &240) << 20));

                if (sample_2 < QB)
                {
                    b->coeffs[coeffs_written] = sample_1;
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
                uint32_t sample_1 = ((uint32_t) buf[j + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 1 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 2 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &15) << 24));

                if (sample_1 < QC)
                {
                    c->coeffs[coeffs_written] = sample_1;
                    coeffs_written++;
                }

                if (coeffs_written == NEWHOPE_N) break;

                uint32_t sample_2 = ((uint32_t) buf[j + 4 + i *SHAKE128_RATE] |
                    ((uint32_t) buf[j + 5 + i *SHAKE128_RATE] << 8) |
                    ((uint32_t) buf[j + 6 + i *SHAKE128_RATE] << 16) |
                    ((uint32_t)(buf[j + 3 + i *SHAKE128_RATE] &240) << 20));

                if (sample_2 < QC)
                {
                    c->coeffs[coeffs_written] = sample_1;
                    coeffs_written++;
                }
            }
        }

        iteration++;
    }
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
 *Description: Generated a random poly_28 with no input.
 *
 *Arguments:   - poly_28 *key_point_polya: pointer to the poly_28 generated mod Q_A
 *             - poly_28 *key_point_polyb: pointer to the poly_28 generated mod Q_B
 *             - poly_28 *key_point_polyc: pointer to the poly_28 generated mod Q_C
 *
 *Returns:     None
 **************************************************/
void lwe_gen_key(poly_28 *key_point_polya, poly_28 *key_point_polyb, poly_28 *key_point_polyc)
{
    uint8_t key_seed[NEWHOPE_SYMBYTES];
    RAND_bytes(key_seed, NEWHOPE_SYMBYTES);
    poly_uniform_ref_poly_28_ABC(key_point_polya, key_point_polyb, key_point_polyc, key_seed);
}

/*************************************************
 *Name:        lwe_gen_key_avx
 *
 *Description: AVX form of lwe_gen_key. Generated a random poly_28 with no input.
 *
 *Arguments:   - poly_28 *key_point_polya: pointer to the poly_28 generated mod Q_A
 *             - poly_28 *key_point_polyb: pointer to the poly_28 generated mod Q_B
 *             - poly_28 *key_point_polyc: pointer to the poly_28 generated mod Q_C
 *
 *Returns:     None
 **************************************************/
void lwe_gen_key_avx(poly_28 *key_point_polya, poly_28 *key_point_polyb, poly_28 *key_point_polyc)
{
    uint8_t key_seed[NEWHOPE_SYMBYTES];
    RAND_bytes(key_seed, NEWHOPE_SYMBYTES);
    poly_uniform_ref_poly_28_ABC_avx(key_point_polya, key_point_polyb, key_point_polyc, key_seed);
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
    lwe_gen_key(&data_header.poly_keya, &data_header.poly_keyb, &data_header.poly_keyc);

    int padded_size = pad_array(message, size);

    poly_uniform_ref_message(data_header.hash, message, padded_size);
    RAND_bytes(ciphertext_hat->iv, IV_LEN);
    int ctx_header_length = gcm_encrypt((uint8_t*) &data_header, sizeof(UAE_lwe_data_header),
        AE_key,
        ciphertext_hat->iv, IV_LEN,
        ciphertext_hat->ctx,
        ciphertext_hat->tag);

    int output_len = kh_prf_encrypt_1_17_ABC(&data_header.poly_keya, &data_header.poly_keyb, &data_header.poly_keyc, message, ciphertext, padded_size);

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
    lwe_gen_key_avx(&data_header.poly_keya, &data_header.poly_keyb, &data_header.poly_keyc);

    int padded_size = pad_array(message, size);

    poly_uniform_ref_message(data_header.hash, message, padded_size);
    RAND_bytes(ciphertext_hat->iv, IV_LEN);
    int ctx_header_length = gcm_encrypt((uint8_t*) &data_header, sizeof(UAE_lwe_data_header),
        AE_key,
        ciphertext_hat->iv, IV_LEN,
        ciphertext_hat->ctx,
        ciphertext_hat->tag);

    int output_len = kh_prf_encrypt_1_17_ABC_avx(&data_header.poly_keya, &data_header.poly_keyb, &data_header.poly_keyc, message, ciphertext, padded_size);

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

    int output_len = kh_prf_decrypt_1_17_ABC(&data_header.poly_keya, &data_header.poly_keyb, &data_header.poly_keyc, ciphertext, decrypted_message, size);
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

    int output_len = kh_prf_decrypt_1_17_ABC_avx(&data_header.poly_keya, &data_header.poly_keyb, &data_header.poly_keyc, ciphertext, decrypted_message, size);
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

    poly_28 poly_key1, poly_key2, poly_key3;
    memcpy(&poly_key1, &data_header.poly_keya, sizeof(poly_28));
    memcpy(&poly_key2, &data_header.poly_keyb, sizeof(poly_28));
    memcpy(&poly_key3, &data_header.poly_keyc, sizeof(poly_28));
    lwe_gen_key(&data_header.poly_keya, &data_header.poly_keyb, &data_header.poly_keyc);

    for (int i = 0; i < NEWHOPE_N; i++) {
        delta->poly_keya.coeffs[i] = barrett_reduce_268369921(data_header.poly_keya.coeffs[i] - poly_key1.coeffs[i]);
        delta->poly_keyb.coeffs[i] = barrett_reduce_268361729(data_header.poly_keyb.coeffs[i] - poly_key2.coeffs[i]);
        delta->poly_keyc.coeffs[i] = barrett_reduce_268271617(data_header.poly_keyc.coeffs[i] - poly_key3.coeffs[i]);
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

    poly_28 poly_key1, poly_key2, poly_key3;
    memcpy(&poly_key1, &data_header.poly_keya, sizeof(poly_28));
    memcpy(&poly_key2, &data_header.poly_keyb, sizeof(poly_28));
    memcpy(&poly_key3, &data_header.poly_keyc, sizeof(poly_28));
    lwe_gen_key_avx(&data_header.poly_keya, &data_header.poly_keyb, &data_header.poly_keyc);

    for (int i = 0; i < NEWHOPE_N; i++) {
        delta->poly_keya.coeffs[i] = barrett_reduce_268369921(data_header.poly_keya.coeffs[i] - poly_key1.coeffs[i]);
        delta->poly_keyb.coeffs[i] = barrett_reduce_268361729(data_header.poly_keyb.coeffs[i] - poly_key2.coeffs[i]);
        delta->poly_keyc.coeffs[i] = barrett_reduce_268271617(data_header.poly_keyc.coeffs[i] - poly_key3.coeffs[i]);
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

    int re_encrypt_length = kh_prf_re_encrypt_1_17_ABC(&delta->poly_keya, &delta->poly_keyb, &delta->poly_keyc, ciphertext1, ciphertext2, size);

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

    int re_encrypt_length = kh_prf_re_encrypt_1_17_ABC_avx(&delta->poly_keya, &delta->poly_keyb, &delta->poly_keyc, ciphertext1, ciphertext2, size);

    return re_encrypt_length;
}

/*************************************************
 *Name:        mulitply_mod_62
 *
 *Description: Calculates multiplication by 2^62
 *
 *Arguments:   - int128_t input_a: input integer
 *
 *Returns:     The product
 **************************************************/
int128_t mulitply_mod_62(int128_t input_a) {
  int128_t output = 0;

  int128_t input_a_low = input_a &BLOCK_62;
  int128_t input_a_high = (input_a>>62);

  output += (input_a_low << 62);
  output += input_a_high*((int128_t)MODP_124_P);

  return output;
}

/*************************************************
 *Name:        mulitply_mod
 *
 *Description: Calculates multiplication with 2 numbers less than Q_ABC
 *
 *Arguments:   - int128_t input_a: input integer a
 *             - int128_t input_b: input integer b
 *
 *Returns:     The product
 **************************************************/
int128_t mulitply_mod(int128_t input_a, int128_t input_b)
{
    int128_t output = 0;

    int128_t input_a_low = input_a &BLOCK_62;
    int128_t input_a_high = (input_a>>62) ;

    int128_t input_b_low = input_b &BLOCK_62;
    int128_t input_b_high = (input_b>>62);

    output += input_a_low*input_b_low; // 124 bits

    output += mulitply_mod_62(input_a_low*input_b_high);
    output += mulitply_mod_62(input_a_high*input_b_low);

    output += (input_a_high*input_b_high*((int128_t)MODP_124_P)); // 125 bits

    return output;
}

/*************************************************
 *Name:        reduce_modq
 *
 *Description: Reduces 128 bit integer by Q_ABC
 *
 *Arguments:   - int128_t input: input integer
 *
 *Returns:     Reduced integer
 **************************************************/
int128_t reduce_modq(int128_t input)
{

    uint128_t sign = (uint128_t) input >> 127;
    input += ((uint128_t)Q_ABC) *sign;

    sign = (uint128_t) input >> 127;

    int128_t output = (input & (uint128_t)BLOCK_84) + mulitply_mod((input >> 84), ((int128_t)MODP_84_P));

    output = output - ((input >> 84)/885*((int128_t)Q_ABC));

    uint128_t diff = (uint128_t) BLOCK_84 - (uint128_t)(output + ((uint128_t)MODP_84_P));

    int128_t delta = mulitply_mod((diff >> 127), (uint128_t)Q_ABC);
    output -= delta;

    return output;
}

/*************************************************
 *Name:        poly_combine_84_ABC
 *
 *Description: Given 3 poly_28 inputs, combine using CRT
 *
 *Arguments:   - poly_28 a: input polynomial in Q_A
 *             - poly_28 b: input polynomial in Q_B
 *             - poly_28 c: input polynomial in Q_C
 *             - poly_56 d: output polynomial in Q_ABC
 *
 *Returns:     none
 **************************************************/
void poly_combine_84_ABC(poly_28 *a, poly_28 *b, poly_28 *c, poly_84 *d) {
  int128_t sign, temp, inter;
  for (int i=0; i<NEWHOPE_N; i++) {
    inter = montgomery_reduce_AB((__int128)a->coeffs[i]*(__int128)QB_QB_INV_A);
    inter += montgomery_reduce_AB((__int128)b->coeffs[i]*(__int128)QB_QA_INV_B);
    inter = reduce_modq(inter);

    sign = (uint128_t) inter >> 127;
    temp = ((int128_t) inter + (sign*Q_AB));

    temp = mulitply_mod((int128_t)temp,(int128_t)QC_QC_INV_AB);
    d->coeffs[i] = reduce_modq(temp);

    sign = (uint32_t) c->coeffs[i] >> 31;
    temp = ((int128_t)c->coeffs[i]+(sign*QC));
    temp = mulitply_mod((int128_t)temp,(int128_t)QAB_QAB_INV_C);
    d->coeffs[i] += reduce_modq(temp);
    d->coeffs[i] = reduce_modq(d->coeffs[i]);
  }
}

/*************************************************
 *Name:        create_product_point_ABC
 *
 *Description: Takes in 3 poly_28 keys and seed of a poly_28, point_seed,
 *             generats 3 poly_28 in mod Q_A, Q_B and Q_C, multiplies then as if they
 *             they are in the NTT domain, then computes the inverse NTT of the product.
 *             FInally combines the 4 poly_28 into a poly_84 mod Q_ABC using CRT.
 *
 *Arguments:   - poly_28 *key_a: pointer to the poly_28 input mod Q_A
 *             - poly_28 *key_b: pointer to the poly_28 input mod Q_B
 *             - poly_28 *key_c: pointer to the poly_28 input mod Q_C
 *             - poly_84 *product_point_poly: pointer to the poly_84 product
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void create_product_point_ABC(poly_28 *key_a, poly_28 *key_b, poly_28 *key_c, poly_84 *product, unsigned char *point_seed)
{
    
    int i;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        point_seed[i] += 1;
        if (point_seed[i] != 0) break;
    }

    poly_28 point_poly_a, point_poly_b, point_poly_c, product_a, product_b, product_c;

    poly_uniform_ref_poly_28_ABC(&point_poly_a, &point_poly_b, &point_poly_c, point_seed);

    poly_basemul_268369921(&product_a, key_a, &point_poly_a);
    poly_basemul_268361729(&product_b, key_b, &point_poly_b);
    poly_basemul_268271617(&product_c, key_c, &point_poly_c);

    poly_invntt_268369921(&product_a);
    poly_invntt_268361729(&product_b);
    poly_invntt_268271617(&product_c);

    poly_combine_84_ABC(&product_a, &product_b, &product_c, product);
}

/*************************************************
 *Name:        create_product_point_ABC_avx
 *
 *Description: AVX form of create_product_point_ABC.
 *             Takes in 3 poly_28 keys and seed of a poly_28, point_seed,
 *             generats 3 poly_28 in mod Q_A, Q_B and Q_C, multiplies then as if they
 *             they are in the NTT domain, then computes the inverse NTT of the product.
 *             FInally combines the 2 poly_28 into a poly_84 mod Q_ABC using CRT.
 *
 *Arguments:   - poly_28 *key_a: pointer to the poly_28 input mod Q_A
 *             - poly_28 *key_b: pointer to the poly_28 input mod Q_B
 *             - poly_28 *key_c: pointer to the poly_28 input mod Q_C
 *             - poly_84 *product_point_poly: pointer to the poly_28 product
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void create_product_point_ABC_avx(poly_28 *key_a, poly_28 *key_b, poly_28 *key_c, poly_84 *product, unsigned char *point_seed)
{
    
    int i;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        point_seed[i] += 1;
        if (point_seed[i] != 0) break;
    }

    poly_28 point_poly_a, point_poly_b, point_poly_c, product_a, product_b, product_c;

    poly_uniform_ref_poly_28_ABC_avx(&point_poly_a, &point_poly_b, &point_poly_c, point_seed);

    poly_basemul_268369921(&product_a, key_a, &point_poly_a);
    poly_basemul_268361729(&product_b, key_b, &point_poly_b);
    poly_basemul_268271617(&product_c, key_c, &point_poly_c);

    poly_invntt_avx_268369921(&product_a);
    poly_invntt_avx_268361729(&product_b);
    poly_invntt_avx_268271617(&product_c);

    poly_combine_84_ABC(&product_a, &product_b, &product_c, product);
}

/*************************************************
 *Name:        poly_uniform_ref_noise_seeds_pseudo_ABC
 *
 *Description: Takes in a 32 bytes seed, generates a poly_84 with shake128 
 *             uniformly random elements in mod Q_ABC. Differs than poly_uniform_ref_poly_28
 *             because it is used to generate the noise poly so the input extseed is different.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_84 *a: pointer to the poly_28 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_noise_seeds_pseudo_ABC(poly_84 *a, const unsigned char *seed)
{
    unsigned int ctr = 0;
    uint64_t val;
    uint64_t state[25];
    uint8_t buf[SHAKE128_RATE];
    uint8_t extseed[(2 *NEWHOPE_SYMBYTES + 2)];
    int i, j, k;

    for (i = 0; i < 2 *NEWHOPE_SYMBYTES + 2; i++) extseed[i] = 0;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        extseed[i] = seed[i];

    int coeffs_written = 0;
    int iteration = 0;
    uint8_t *a_byte = (int8_t*) a;
    uint128_t sample;

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

        for (j = 0; j <= SHAKE128_RATE - NOISE_MAX_BYTES && coeffs_written < NEWHOPE_N; j += NOISE_MAX_BYTES)
        {
          sample = ((uint128_t) buf[j] | ((uint128_t)(buf[j + 1]&15) << 8));
          if (sample < NOISE_MULT_MAX)
          {
              a->coeffs[coeffs_written] = sample/NOISE_MAX_FACTOR;
              coeffs_written++;
          }
          if (coeffs_written == NEWHOPE_N) break;

          sample = ((uint128_t) buf[j+2] | ((uint128_t)(buf[j + 1]&240) <<4));
          if (sample < NOISE_MULT_MAX)
          {
              a->coeffs[coeffs_written] = sample/NOISE_MAX_FACTOR;
              coeffs_written++;
          }

        }

        iteration++;
    }
}

/*************************************************
 *Name:        poly_uniform_ref_noise_seeds_pseudo_ABC
 *
 *Description: AVX2 form of poly_uniform_ref_noise_seeds_pseudo_ABC.
 *             Takes in a 32 bytes seed, generates a poly_84 with shake128 
 *             uniformly random elements in mod Q_ABC. Differs than poly_uniform_ref_poly_28
 *             because it is used to generate the noise poly so the input extseed is different.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_84 *a: pointer to the poly_28 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_noise_seeds_pseudo_ABC_avx(poly_84 *a, const unsigned char *seed)
{
    uint8_t buf[4 *SHAKE128_RATE];
    uint8_t extseed0[2 *NEWHOPE_SYMBYTES + 2];
    uint8_t extseed1[2 *NEWHOPE_SYMBYTES + 2];
    uint8_t extseed2[2 *NEWHOPE_SYMBYTES + 2];
    uint8_t extseed3[2 *NEWHOPE_SYMBYTES + 2];
    int i, j, k;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        extseed0[i] = seed[i];
        extseed1[i] = seed[i];
        extseed2[i] = seed[i];
        extseed3[i] = seed[i];
    }

    unsigned int coeffs_written = 0;
    unsigned int iteration = 0;

    uint128_t val;
    uint128_t sample;

    uint128_t used = 0;
    uint128_t tossed = 0;

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
            for (j = 0; j <= SHAKE128_RATE - NOISE_MAX_BYTES && coeffs_written < NEWHOPE_N; j += NOISE_MAX_BYTES)
            {
              sample = ((uint128_t) buf[j + i *SHAKE128_RATE] | ((uint128_t)(buf[j + 1 + i *SHAKE128_RATE]&15) << 8));
              if (sample < NOISE_MULT_MAX)
              {
                  a->coeffs[coeffs_written] = sample/NOISE_MAX_FACTOR;
                  coeffs_written++;
              }
              if (coeffs_written == NEWHOPE_N) break;

              sample = ((uint128_t) buf[j + 2 + i *SHAKE128_RATE] | ((uint128_t)(buf[j + 1 + i *SHAKE128_RATE]&240) <<4));
              if (sample < NOISE_MULT_MAX)
              {
                  a->coeffs[coeffs_written] = sample/NOISE_MAX_FACTOR;
                  coeffs_written++;
              }

            }
        }

        iteration++;
    }
}

/*************************************************
 *Name:        kh_prf_encrypt_1_17_ABC
 *
 *Description: KH_PRF to encrypt buf using key_point_poly_a, key_point_poly_b, and key_point_poly_c. 
 *             Assumes that the message is padded. The lower 17 and highest bits are
 *             zero before the addition of the product coefficient.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the key mod Q_B
 *             - poly_28 *key_point_poly_c: pointer to the key mod Q_C
 *             - uint8_t *buf: pointer to the message
 *             - uint8_t *out: pointer to the ciphertext
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_encrypt_1_17_ABC(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_84 product_poly;
    poly_84 noise_poly;

    int bytes_processed = 0;
    int bytes_written = 0;

    uint128_t sample_1, sample_2, sample_3, sample_4;
    while (bytes_processed < size)
    {
        create_product_point_ABC(key_point_poly_a, key_point_poly_b, key_point_poly_c, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_ABC(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += COEFFS_PER_BLOCK)
        {
            
            sample_1 = 0;
            for (int j=0; j<8; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8*j));
            sample_1 |= (((uint128_t) buf[bytes_processed + 32]&3) << (8*8));
            sample_1 = (sample_1<<17) + NOISE_MAX;

            sample_2 = 0;
            for (int j=0; j<8; j++) sample_2 |= ((uint128_t) buf[bytes_processed + j+8] << (8*j));
            sample_2 |= (((uint128_t) buf[bytes_processed + 32]&12) << (8*8-2));
            sample_2 = (sample_2<<17) + NOISE_MAX;

            sample_3 = 0;
            for (int j=0; j<8; j++) sample_3 |= ((uint128_t) buf[bytes_processed + j+16] << (8*j));
            sample_3 |= (((uint128_t) buf[bytes_processed + 32]&48) << (8*8-4));
            sample_3 = (sample_3<<17) + NOISE_MAX;

            sample_4 = 0;
            for (int j=0; j<8; j++) sample_4 |= ((uint128_t) buf[bytes_processed + j+24] << (8*j));
            sample_4 |= (((uint128_t) buf[bytes_processed + 32]&192) << (8*8-6));
            sample_4 = (sample_4<<17) + NOISE_MAX;

            sample_1 = reduce_modq(sample_1 + (uint128_t) product_poly.coeffs[i] + (uint128_t) noise_poly.coeffs[i]);
            sample_2 = reduce_modq(sample_2 + (uint128_t) product_poly.coeffs[i + 1] + (uint128_t) noise_poly.coeffs[i + 1]);
            sample_3 = reduce_modq(sample_3 + (uint128_t) product_poly.coeffs[i + 2] + (uint128_t) noise_poly.coeffs[i + 2]);
            sample_4 = reduce_modq(sample_4 + (uint128_t) product_poly.coeffs[i + 3] + (uint128_t) noise_poly.coeffs[i + 3]);

            if (sample_1 > (uint128_t) Q_ABC) printf("SAMPLE TOO BIG\n");
            

            out[bytes_written + 40] = (sample_1&15) | ((sample_2&15)<<4);
            out[bytes_written + 41] = (sample_3&15) | ((sample_4&15)<<4);

            sample_1 = (sample_1 >> 4);
            sample_2 = (sample_2 >> 4);
            sample_3 = (sample_3 >> 4);
            sample_4 = (sample_4 >> 4);

            for (int j=0; j<10; j++) out[bytes_written + j     ] = (sample_1 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_written + j + 10] = (sample_2 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_written + j + 20] = (sample_3 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_written + j + 30] = (sample_4 &((uint128_t)255ul << (8*j))) >> (8*j);
            
            bytes_processed += PAD_SIZE;
            bytes_written += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_encrypt_1_17_ABC_avx
 *
 *Description: AVX form of kh_prf_encrypt_1_17_ABC.
 *             KH_PRF to encrypt buf using key_point_poly_a, key_point_poly_b, and key_point_poly_c.  
 *             Assumes that the message is padded. The lower 17 and highest bits are
 *             zero before the addition of the product coefficient.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the key mod Q_B
 *             - poly_28 *key_point_poly_c: pointer to the key mod Q_C
 *             - uint8_t *buf: pointer to the message
 *             - uint8_t *out: pointer to the ciphertext
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_encrypt_1_17_ABC_avx(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_84 product_poly;
    poly_84 noise_poly;

    int bytes_processed = 0;
    int bytes_written = 0;

    uint128_t sample_1, sample_2, sample_3, sample_4;
    while (bytes_processed < size)
    {
        create_product_point_ABC_avx(key_point_poly_a, key_point_poly_b, key_point_poly_c, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_ABC_avx(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += COEFFS_PER_BLOCK)
        {
            
            sample_1 = 0;
            for (int j=0; j<8; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8*j));
            sample_1 |= (((uint128_t) buf[bytes_processed + 32]&3) << (8*8));
            sample_1 = (sample_1<<17) + NOISE_MAX;

            sample_2 = 0;
            for (int j=0; j<8; j++) sample_2 |= ((uint128_t) buf[bytes_processed + j+8] << (8*j));
            sample_2 |= (((uint128_t) buf[bytes_processed + 32]&12) << (8*8-2));
            sample_2 = (sample_2<<17) + NOISE_MAX;

            sample_3 = 0;
            for (int j=0; j<8; j++) sample_3 |= ((uint128_t) buf[bytes_processed + j+16] << (8*j));
            sample_3 |= (((uint128_t) buf[bytes_processed + 32]&48) << (8*8-4));
            sample_3 = (sample_3<<17) + NOISE_MAX;

            sample_4 = 0;
            for (int j=0; j<8; j++) sample_4 |= ((uint128_t) buf[bytes_processed + j+24] << (8*j));
            sample_4 |= (((uint128_t) buf[bytes_processed + 32]&192) << (8*8-6));
            sample_4 = (sample_4<<17) + NOISE_MAX;

            sample_1 = reduce_modq(sample_1 + (uint128_t) product_poly.coeffs[i] + (uint128_t) noise_poly.coeffs[i]);
            sample_2 = reduce_modq(sample_2 + (uint128_t) product_poly.coeffs[i + 1] + (uint128_t) noise_poly.coeffs[i + 1]);
            sample_3 = reduce_modq(sample_3 + (uint128_t) product_poly.coeffs[i + 2] + (uint128_t) noise_poly.coeffs[i + 2]);
            sample_4 = reduce_modq(sample_4 + (uint128_t) product_poly.coeffs[i + 3] + (uint128_t) noise_poly.coeffs[i + 3]);

            if (sample_1 > (uint128_t) Q_ABC) printf("SAMPLE TOO BIG\n");
            

            out[bytes_written + 40] = (sample_1&15) | ((sample_2&15)<<4);
            out[bytes_written + 41] = (sample_3&15) | ((sample_4&15)<<4);

            sample_1 = (sample_1 >> 4);
            sample_2 = (sample_2 >> 4);
            sample_3 = (sample_3 >> 4);
            sample_4 = (sample_4 >> 4);

            for (int j=0; j<10; j++) out[bytes_written + j     ] = (sample_1 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_written + j + 10] = (sample_2 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_written + j + 20] = (sample_3 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_written + j + 30] = (sample_4 &((uint128_t)255ul << (8*j))) >> (8*j);
            
            bytes_processed += PAD_SIZE;
            bytes_written += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_decrypt_1_17_ABC
 *
 *Description: KH_PRF to decrypt buf using key_point_poly_a,  key_point_poly_b, and key_point_poly_c. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the key mod Q_B
 *             - poly_28 *key_point_poly_c: pointer to the key mod Q_C
 *             - uint8_t *buf: pointer to the ciphertext
 *             - uint8_t *out: pointer to the decrypted message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int kh_prf_decrypt_1_17_ABC(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_84 product_poly;

    int bytes_processed = 0;
    int bytes_written = 0;

    uint128_t sample_1, sample_2, sample_3, sample_4;
    while (bytes_processed < size)
    {
        create_product_point_ABC(key_point_poly_a, key_point_poly_b, key_point_poly_c, &product_poly, (unsigned char *) &point_seed);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += COEFFS_PER_BLOCK)
        {
            sample_1 = 0;
            for (int j=0; j<10; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8*j));
            sample_1 = (sample_1<<4) | (buf[bytes_processed +40]&15);

            sample_2 = 0;
            for (int j=0; j<10; j++) sample_2 |= ((uint128_t) buf[bytes_processed + j + 10] << (8*j));
            sample_2 = (sample_2<<4) | (buf[bytes_processed +40]>>4);

            sample_3 = 0;
            for (int j=0; j<10; j++) sample_3 |= ((uint128_t) buf[bytes_processed + j + 20] << (8*j));
            sample_3 = (sample_3<<4) | (buf[bytes_processed +41]&15);

            sample_4 = 0;
            for (int j=0; j<10; j++) sample_4 |= ((uint128_t) buf[bytes_processed + j + 30] << (8*j));
            sample_4 = (sample_4<<4) | (buf[bytes_processed +41]>>4);

            sample_1 = reduce_modq(sample_1 + (uint128_t)Q_ABC - (uint128_t) product_poly.coeffs[i]);
            sample_2 = reduce_modq(sample_2 + (uint128_t)Q_ABC - (uint128_t) product_poly.coeffs[i + 1]);
            sample_3 = reduce_modq(sample_3 + (uint128_t)Q_ABC - (uint128_t) product_poly.coeffs[i + 2]);
            sample_4 = reduce_modq(sample_4 + (uint128_t)Q_ABC - (uint128_t) product_poly.coeffs[i + 3]);

            sample_1 = sample_1>> 17;
            sample_2 = sample_2>> 17;
            sample_3 = sample_3>> 17;
            sample_4 = sample_4>> 17;

            for (int j=0; j<8; j++) out[bytes_written + j     ] = (sample_1 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<8; j++) out[bytes_written + j + 8] = (sample_2 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<8; j++) out[bytes_written + j + 16] = (sample_3 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<8; j++) out[bytes_written + j + 24] = (sample_4 &((uint128_t)255ul << (8*j))) >> (8*j);
            out[bytes_written + 32] = (sample_1 >> (8*8)) | ((sample_2 >> (8*8-2))&12) |((sample_3 >> (8*8-4))&48) |((sample_4 >> (8*8-6))&192);


            bytes_processed += SAMPLE_BLOCK_SIZE;
            bytes_written += PAD_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_decrypt_1_17_ABC_avx
 *
 *Description: AVX form of kh_prf_decrypt_1_17_ABC.
 *             KH_PRF to decrypt buf using key_point_poly_a,  key_point_poly_b, and key_point_poly_c. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the key mod Q_B
 *             - poly_28 *key_point_poly_c: pointer to the key mod Q_C
 *             - uint8_t *buf: pointer to the ciphertext
 *             - uint8_t *out: pointer to the decrypted message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int kh_prf_decrypt_1_17_ABC_avx(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_84 product_poly;

    int bytes_processed = 0;
    int bytes_written = 0;

    uint128_t sample_1, sample_2, sample_3, sample_4;
    while (bytes_processed < size)
    {
        create_product_point_ABC_avx(key_point_poly_a, key_point_poly_b, key_point_poly_c, &product_poly, (unsigned char *) &point_seed);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += COEFFS_PER_BLOCK)
        {
            sample_1 = 0;
            for (int j=0; j<10; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8*j));
            sample_1 = (sample_1<<4) | (buf[bytes_processed +40]&15);

            sample_2 = 0;
            for (int j=0; j<10; j++) sample_2 |= ((uint128_t) buf[bytes_processed + j + 10] << (8*j));
            sample_2 = (sample_2<<4) | (buf[bytes_processed +40]>>4);

            sample_3 = 0;
            for (int j=0; j<10; j++) sample_3 |= ((uint128_t) buf[bytes_processed + j + 20] << (8*j));
            sample_3 = (sample_3<<4) | (buf[bytes_processed +41]&15);

            sample_4 = 0;
            for (int j=0; j<10; j++) sample_4 |= ((uint128_t) buf[bytes_processed + j + 30] << (8*j));
            sample_4 = (sample_4<<4) | (buf[bytes_processed +41]>>4);

            sample_1 = reduce_modq(sample_1 + (uint128_t)Q_ABC - (uint128_t) product_poly.coeffs[i]);
            sample_2 = reduce_modq(sample_2 + (uint128_t)Q_ABC - (uint128_t) product_poly.coeffs[i + 1]);
            sample_3 = reduce_modq(sample_3 + (uint128_t)Q_ABC - (uint128_t) product_poly.coeffs[i + 2]);
            sample_4 = reduce_modq(sample_4 + (uint128_t)Q_ABC - (uint128_t) product_poly.coeffs[i + 3]);

            sample_1 = sample_1>> 17;
            sample_2 = sample_2>> 17;
            sample_3 = sample_3>> 17;
            sample_4 = sample_4>> 17;

            for (int j=0; j<8; j++) out[bytes_written + j     ] = (sample_1 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<8; j++) out[bytes_written + j + 8] = (sample_2 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<8; j++) out[bytes_written + j + 16] = (sample_3 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<8; j++) out[bytes_written + j + 24] = (sample_4 &((uint128_t)255ul << (8*j))) >> (8*j);
            out[bytes_written + 32] = (sample_1 >> (8*8)) | ((sample_2 >> (8*8-2))&12) |((sample_3 >> (8*8-4))&48) |((sample_4 >> (8*8-6))&192);


            bytes_processed += SAMPLE_BLOCK_SIZE;
            bytes_written += PAD_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_re_encrypt_1_17_ABC
 *
 *Description: KH_PRF to re_encrypt buf using key_point_poly_a,  key_point_poly_b, and key_point_poly_c. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the delta of the new and old key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the delta of the new and old key mod Q_B
 *             - poly_28 *key_point_poly_c: pointer to the delta of the new and old key mod Q_C
 *             - uint8_t *buf: pointer to the old ciphertext
 *             - uint8_t *out: pointer to the new ciphertext
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int kh_prf_re_encrypt_1_17_ABC(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_84 product_poly;
    poly_84 noise_poly;

    int bytes_processed = 0;

    uint128_t sample_1, sample_2, sample_3, sample_4;
    while (bytes_processed < size)
    {
        create_product_point_ABC(key_point_poly_a, key_point_poly_b, key_point_poly_c, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_ABC(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += COEFFS_PER_BLOCK)
        {
            sample_1 = 0;
            for (int j=0; j<10; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8*j));
            sample_1 = (sample_1<<4) | (buf[bytes_processed +40]&15);

            sample_2 = 0;
            for (int j=0; j<10; j++) sample_2 |= ((uint128_t) buf[bytes_processed + j + 10] << (8*j));
            sample_2 = (sample_2<<4) | (buf[bytes_processed +40]>>4);

            sample_3 = 0;
            for (int j=0; j<10; j++) sample_3 |= ((uint128_t) buf[bytes_processed + j + 20] << (8*j));
            sample_3 = (sample_3<<4) | (buf[bytes_processed +41]&15);

            sample_4 = 0;
            for (int j=0; j<10; j++) sample_4 |= ((uint128_t) buf[bytes_processed + j + 30] << (8*j));
            sample_4 = (sample_4<<4) | (buf[bytes_processed +41]>>4);

            sample_1 = reduce_modq(sample_1 + (uint128_t) product_poly.coeffs[i] + (uint128_t) noise_poly.coeffs[i]);
            sample_2 = reduce_modq(sample_2 + (uint128_t) product_poly.coeffs[i + 1] + (uint128_t) noise_poly.coeffs[i + 1]);
            sample_3 = reduce_modq(sample_3 + (uint128_t) product_poly.coeffs[i + 2] + (uint128_t) noise_poly.coeffs[i + 2]);
            sample_4 = reduce_modq(sample_4 + (uint128_t) product_poly.coeffs[i + 3] + (uint128_t) noise_poly.coeffs[i + 3]);;

            out[bytes_processed + 40] = (sample_1&15) | ((sample_2&15)<<4);
            out[bytes_processed + 41] = (sample_3&15) | ((sample_4&15)<<4);

            sample_1 = (sample_1 >> 4);
            sample_2 = (sample_2 >> 4);
            sample_3 = (sample_3 >> 4);
            sample_4 = (sample_4 >> 4);

            for (int j=0; j<10; j++) out[bytes_processed + j     ] = (sample_1 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_processed + j + 10] = (sample_2 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_processed + j + 20] = (sample_3 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_processed + j + 30] = (sample_4 &((uint128_t)255ul << (8*j))) >> (8*j);


            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_processed;
}

/*************************************************
 *Name:        kh_prf_re_encrypt_1_17_ABC_avx
 *
 *Description: AVX form of kh_prf_re_encrypt_1_17_ABC.
 *             KH_PRF to re_encrypt buf using key_point_poly_a,  key_point_poly_b, and key_point_poly_c. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_28 *key_point_poly_a: pointer to the delta of the new and old key mod Q_A
 *             - poly_28 *key_point_poly_b: pointer to the delta of the new and old key mod Q_B
 *             - poly_28 *key_point_poly_c: pointer to the delta of the new and old key mod Q_C
 *             - uint8_t *buf: pointer to the old ciphertext
 *             - uint8_t *out: pointer to the new ciphertex
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int kh_prf_re_encrypt_1_17_ABC_avx(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_84 product_poly;
    poly_84 noise_poly;

    int bytes_processed = 0;

    uint128_t sample_1, sample_2, sample_3, sample_4;
    while (bytes_processed < size)
    {
        create_product_point_ABC_avx(key_point_poly_a, key_point_poly_b, key_point_poly_c, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_ABC_avx(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += COEFFS_PER_BLOCK)
        {
            sample_1 = 0;
            for (int j=0; j<10; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8*j));
            sample_1 = (sample_1<<4) | (buf[bytes_processed +40]&15);

            sample_2 = 0;
            for (int j=0; j<10; j++) sample_2 |= ((uint128_t) buf[bytes_processed + j + 10] << (8*j));
            sample_2 = (sample_2<<4) | (buf[bytes_processed +40]>>4);

            sample_3 = 0;
            for (int j=0; j<10; j++) sample_3 |= ((uint128_t) buf[bytes_processed + j + 20] << (8*j));
            sample_3 = (sample_3<<4) | (buf[bytes_processed +41]&15);

            sample_4 = 0;
            for (int j=0; j<10; j++) sample_4 |= ((uint128_t) buf[bytes_processed + j + 30] << (8*j));
            sample_4 = (sample_4<<4) | (buf[bytes_processed +41]>>4);

            sample_1 = reduce_modq(sample_1 + (uint128_t) product_poly.coeffs[i] + (uint128_t) noise_poly.coeffs[i]);
            sample_2 = reduce_modq(sample_2 + (uint128_t) product_poly.coeffs[i + 1] + (uint128_t) noise_poly.coeffs[i + 1]);
            sample_3 = reduce_modq(sample_3 + (uint128_t) product_poly.coeffs[i + 2] + (uint128_t) noise_poly.coeffs[i + 2]);
            sample_4 = reduce_modq(sample_4 + (uint128_t) product_poly.coeffs[i + 3] + (uint128_t) noise_poly.coeffs[i + 3]);;

            out[bytes_processed + 40] = (sample_1&15) | ((sample_2&15)<<4);
            out[bytes_processed + 41] = (sample_3&15) | ((sample_4&15)<<4);

            sample_1 = (sample_1 >> 4);
            sample_2 = (sample_2 >> 4);
            sample_3 = (sample_3 >> 4);
            sample_4 = (sample_4 >> 4);

            for (int j=0; j<10; j++) out[bytes_processed + j     ] = (sample_1 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_processed + j + 10] = (sample_2 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_processed + j + 20] = (sample_3 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<10; j++) out[bytes_processed + j + 30] = (sample_4 &((uint128_t)255ul << (8*j))) >> (8*j);


            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_processed;
}