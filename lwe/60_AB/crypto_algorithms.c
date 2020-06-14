#include "crypto_algorithms.h"
#include "fips202.h"

/*************************************************
 *Name:        poly_uniform_ref_poly_60_AB
 *
 *Description: Takes in a 32 bytes seed, generates 2 poly_60 with shake128 
 *             uniformly random elements in mod QA for the first, mod QB for the second.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_60 *a: pointer to the poly_28 to be generated mod QA
 *             - poly_60 *b: pointer to the poly_28 to be generated mod QB
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_poly_60_AB(poly_60 *a, poly_60 *b, const unsigned char *seed)
{
    unsigned int ctr = 0;
    uint64_t val;
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
        if (iteration == 65536) printf("ERROR: poly_uniform_ref_poly_60: iteration hit its limit\n");

        extseed[NEWHOPE_SYMBYTES] = iteration; /*domain-separate the 16 independent calls */

        if (extseed[NEWHOPE_SYMBYTES] == 0) extseed[NEWHOPE_SYMBYTES + 1]++;

        shake128_absorb(state, extseed, NEWHOPE_SYMBYTES + 1);
        shake128_squeezeblocks(buf, 1, state);

        for (j = 0; j < SHAKE128_RATE - SAMPLE_BLOCK_SIZE && coeffs_written < NEWHOPE_N; j += SAMPLE_BLOCK_SIZE)
        {

            uint64_t sample_1 = ((uint64_t) buf[j] |
                ((uint64_t) buf[j + 1] << 8) |
                ((uint64_t) buf[j + 2] << 16) |
                ((uint64_t) buf[j + 3] << 24) |
                ((uint64_t) buf[j + 4] << 32) |
                ((uint64_t) buf[j + 5] << 40) |
                ((uint64_t) buf[j + 6] << 48) |
                ((uint64_t)(buf[j + 7] &15) << 56));

            if (sample_1 < QA)
            {
                a->coeffs[coeffs_written] = sample_1;
                coeffs_written++;
            }

            if (coeffs_written == NEWHOPE_N) break;

            uint64_t sample_2 = ((uint64_t) buf[j + 8] |
                ((uint64_t) buf[j + 9] << 8) |
                ((uint64_t) buf[j + 10] << 16) |
                ((uint64_t) buf[j + 11] << 24) |
                ((uint64_t) buf[j + 12] << 32) |
                ((uint64_t) buf[j + 13] << 40) |
                ((uint64_t) buf[j + 14] << 48) |
                ((uint64_t)(buf[j + 7] &240) << 52));
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
        if (iteration == 65536) printf("ERROR: poly_uniform_ref_poly_60: iteration hit its limit\n");

        extseed[NEWHOPE_SYMBYTES] = iteration; /*domain-separate the 16 independent calls */

        if (extseed[NEWHOPE_SYMBYTES] == 0) extseed[NEWHOPE_SYMBYTES + 1]++;

        shake128_absorb(state, extseed, NEWHOPE_SYMBYTES + 1);
        shake128_squeezeblocks(buf, 1, state);

        for (j = 0; j < SHAKE128_RATE - SAMPLE_BLOCK_SIZE && coeffs_written < NEWHOPE_N; j += SAMPLE_BLOCK_SIZE)
        {

            uint64_t sample_1 = ((uint64_t) buf[j] |
                ((uint64_t) buf[j + 1] << 8) |
                ((uint64_t) buf[j + 2] << 16) |
                ((uint64_t) buf[j + 3] << 24) |
                ((uint64_t) buf[j + 4] << 32) |
                ((uint64_t) buf[j + 5] << 40) |
                ((uint64_t) buf[j + 6] << 48) |
                ((uint64_t)(buf[j + 7] &15) << 56));

            if (sample_1 < QB)
            {
                b->coeffs[coeffs_written] = sample_1;
                coeffs_written++;
            }

            if (coeffs_written == NEWHOPE_N) break;

            uint64_t sample_2 = ((uint64_t) buf[j + 8] |
                ((uint64_t) buf[j + 9] << 8) |
                ((uint64_t) buf[j + 10] << 16) |
                ((uint64_t) buf[j + 11] << 24) |
                ((uint64_t) buf[j + 12] << 32) |
                ((uint64_t) buf[j + 13] << 40) |
                ((uint64_t) buf[j + 14] << 48) |
                ((uint64_t)(buf[j + 7] &240) << 52));
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
 *Name:        lwe_gen_key
 *
 *Description: Generated 2 random poly_60 with no input.
 *
 *Arguments:   - poly_60 *key_point_polya: pointer to the poly_60 generated mod Q_A
 *             - poly_60 *key_point_polyb: pointer to the poly_60 generated mod Q_B
 *
 *Returns:     None
 **************************************************/
void lwe_gen_key(poly_60 *key_point_polya, poly_60 *key_point_polyb)
{
    uint8_t key_seed[NEWHOPE_SYMBYTES] = {0};
    RAND_bytes(key_seed, NEWHOPE_SYMBYTES);
    poly_uniform_ref_poly_60_AB(key_point_polya, key_point_polyb, key_seed);
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
    lwe_gen_key(&data_header.poly_keya, &data_header.poly_keyb);

    int padded_size = pad_array(message, size);

    poly_uniform_ref_message(data_header.hash, message, padded_size);
    RAND_bytes(ciphertext_hat->iv, IV_LEN);
    int ctx_header_length = gcm_encrypt((uint8_t*) &data_header, sizeof(UAE_lwe_data_header),
        AE_key,
        ciphertext_hat->iv, IV_LEN,
        ciphertext_hat->ctx,
        ciphertext_hat->tag);

    int output_len = kh_prf_encrypt_1_17_AB(&data_header.poly_keya, &data_header.poly_keyb, message, ciphertext, padded_size);

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

    int output_len = kh_prf_decrypt_1_17_AB(&data_header.poly_keya, &data_header.poly_keyb, ciphertext, decrypted_message, size);
    uint8_t hash[SHAKE128_RATE];

    poly_uniform_ref_message(hash, decrypted_message, output_len);

    for (int i = 0; i < SHAKE128_RATE; i++)
    {
        if (data_header.hash[i] != hash[i])
        {
            printf("HASH DOES NOT MATCH %d %d %d\n", i, data_header.hash[i], hash[i]);
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

    poly_60 poly_key1, poly_key2;
    memcpy(&poly_key1, &data_header.poly_keya, sizeof(poly_60));
    memcpy(&poly_key2, &data_header.poly_keyb, sizeof(poly_60));
    lwe_gen_key(&data_header.poly_keya, &data_header.poly_keyb);

    for (int i = 0; i < NEWHOPE_N; i++) {
        delta->poly_keya.coeffs[i] = barrett_reduce_A(data_header.poly_keya.coeffs[i] - poly_key1.coeffs[i]);
        delta->poly_keyb.coeffs[i] = barrett_reduce_B(data_header.poly_keyb.coeffs[i] - poly_key2.coeffs[i]);
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

    int re_encrypt_length = kh_prf_re_encrypt_1_17_AB(&delta->poly_keya, &delta->poly_keyb, ciphertext1, ciphertext2, size);

    return re_encrypt_length;
}

/*************************************************
 *Name:        mulitply_mod_80
 *
 *Description: Calculates multiplication by 2^80
 *             Expects input to be 80 bits.
 *
 *Arguments:   - int128_t input_a: input integer
 *
 *Returns:     The product
 **************************************************/
int128_t mulitply_mod_80(int128_t input_a) {
  int128_t output = 0;

  int128_t input_a_low = input_a &block_40;
  int128_t input_a_med = (input_a>>40) &block_40;

  output += (input_a_low<<80);
  output += (((int128_t)MODP)*input_a_med);

  return output;
}

/*************************************************
 *Name:        mulitply_mod_120
 *
 *Description: Calculates multiplication by 2^120
 *             Expects input to be 80 bits.
 *
 *Arguments:   - int128_t input_a: input integer
 *
 *Returns:     The product
 **************************************************/
int128_t mulitply_mod_120(int128_t input_a) {
  int128_t output = 0;

  int128_t input_a_low = input_a &block_40;
  int128_t input_a_med = (input_a>>40) &block_40;

  output += input_a_low*((int128_t)MODP);
  output += (input_a_med*((int128_t)MODP_LOW_40))<<40;

  output += mulitply_mod_80(input_a_med*((int128_t)MODP_HIGH_40));

  return output;
}

/*************************************************
 *Name:        mulitply_mod_160
 *
 *Description: Calculates multiplication by 2^160
 *             Expects input to be 80 bits.
 *
 *Arguments:   - int128_t input_a: input integer
 *
 *Returns:     The product
 **************************************************/
int128_t mulitply_mod_160(int128_t input_a) {
  int128_t output = 0;

  int128_t input_a_low = input_a &block_40;
  int128_t input_a_med = (input_a>>40) &block_40;

  output += (input_a_low*((int128_t)MODP_LOW_40))<<40;
  output += mulitply_mod_80(input_a_low*((int128_t)MODP_HIGH_40));
  output += mulitply_mod_80(input_a_med*((int128_t)MODP_LOW_40));

  output += mulitply_mod_120(input_a_med*((int128_t)MODP_HIGH_40));

  return output;
}

/*************************************************
 *Name:        mulitply_mod
 *
 *Description: Calculates multiplication with 2 numbers less than Q_AB
 *
 *Arguments:   - int128_t input_a: input integer a
 *             - int128_t input_b: input integer b
 *
 *Returns:     The product
 **************************************************/
int128_t mulitply_mod(int128_t input_a, int128_t input_b)
{
    int128_t output = 0;

    int128_t input_a_low = input_a &block_40;
    int128_t input_a_med = (input_a>>40) &block_40;
    int128_t input_a_high = input_a >> 80;

    int128_t input_b_low = input_b &block_40;
    int128_t input_b_med = (input_b>>40) &block_40;
    int128_t input_b_high = input_b >> 80;

    output += input_a_low*input_b_low;

    output += (input_a_low*input_b_med)<<40;
    output += (input_a_med*input_b_low)<<40;

    output += mulitply_mod_80(input_a_low*input_b_high);
    output += mulitply_mod_80(input_a_med*input_b_med);
    output += mulitply_mod_80(input_a_high*input_b_low);

    output += mulitply_mod_120(input_a_med*input_b_high);
    output += mulitply_mod_120(input_a_high*input_b_med);

    output += mulitply_mod_160(input_a_high*input_b_high);

    return output;
}

/*************************************************
 *Name:        reduce_modq
 *
 *Description: Reduces 128 bit integer by Q_AB
 *
 *Arguments:   - int128_t input: input integer
 *
 *Returns:     Reduced integer
 **************************************************/
int128_t reduce_modq(int128_t input)
{

    uint128_t sign = (uint128_t) input >> 127;
    input += ((uint128_t)Q_AB) *sign;

    sign = (uint128_t) input >> 127;

    int128_t output = (input & (uint128_t)BLOCK_120) + (input >> 120)*((int128_t)MODP);
    uint128_t diff = (uint128_t) BLOCK_120 - (uint128_t)(output + ((int128_t)MODP));

    sign = (uint128_t)(diff >> 127);
    int128_t delta = ((uint128_t)Q_AB)*sign;
    output -= delta;

    return output;
}

/*************************************************
 *Name:        poly_combine_120_AB
 *
 *Description: Given 2 poly_60 inputs, combine using CRT
 *
 *Arguments:   - poly_60 a: input polynomial in Q_A
 *             - poly_60 b: input polynomial in Q_B
 *             - poly_60 c: output polynomial in Q_AB
 *
 *Returns:     none
 **************************************************/
void poly_combine_120_AB(poly_60 *a, poly_60 *b, poly_120 *c) {
    int128_t temp;

    uint64_t sign;
    for (int i=0; i<NEWHOPE_N; i++) {
        sign = (uint64_t) a->coeffs[i] >> 63;
        a->coeffs[i] += sign*QA;
        sign = (uint64_t) b->coeffs[i] >> 63;
        b->coeffs[i] += sign*QB;

        temp = mulitply_mod((__int128)a->coeffs[i],(__int128)QB_QB_INV_A);
        c->coeffs[i] = (temp);

        temp = mulitply_mod((__int128)b->coeffs[i],QA_QA_INV_B);
        c->coeffs[i] += (temp);
        c->coeffs[i] = reduce_modq(c->coeffs[i]);
    }
}

/*************************************************
 *Name:        create_product_point_AB
 *
 *Description: Takes in 2 poly_60 keys and seed of a poly_60, point_seed,
 *             generats 2 poly_60 in mod Q_A and Q_B, multiplies then as if they
 *             they are in the NTT domain, then computes the inverse NTT of the product.
 *             FInally combines the 2 poly_60 into a poly_120 mod Q_AB using CRT.
 *
 *Arguments:   - poly_60 *key_a: pointer to the poly_60 input mod Q_A
 *             - poly_60 *key_b: pointer to the poly_60 input mod Q_B
 *             - poly_120 *product_point_poly: pointer to the poly_120 product
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void create_product_point_AB(poly_60 *key_a, poly_60 *key_b, poly_120 *product, unsigned char *point_seed)
{
    int i;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        point_seed[i] += 1;
        if (point_seed[i] != 0) break;
    }

    poly_60 point_poly_a, point_poly_b, product_a, product_b;

    poly_uniform_ref_poly_60_AB(&point_poly_a, &point_poly_b, point_seed);

    poly_basemul_A(&product_a, key_a, &point_poly_a);
    poly_basemul_B(&product_b, key_b, &point_poly_b);

    poly_invntt_A(&product_a);
    poly_invntt_B(&product_b);

    poly_combine_120_AB(&product_a, &product_b, product);
}

/*************************************************
 *Name:        poly_uniform_ref_noise_seeds_pseudo_AB
 *
 *Description: Takes in a 32 bytes seed, generates a poly_120 with shake128 
 *             uniformly random elements in mod Q_AB. Differs than poly_uniform_ref_poly_28
 *             because it is used to generate the noise poly so the input extseed is different.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_120 *a: pointer to the poly_28 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_noise_seeds_pseudo_AB(poly_120 *a, const unsigned char *seed)
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
          sample = ((uint64_t) buf[j] | ((uint64_t)(buf[j + 1]&15) << 8));
          if (sample < NOISE_MULT_MAX)
          {
              a->coeffs[coeffs_written] = sample/NOISE_MAX_FACTOR;
              coeffs_written++;
          }
          if (coeffs_written == NEWHOPE_N) break;

          sample = ((uint64_t) buf[j+2] | ((uint64_t)(buf[j + 1]&240) <<4));
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
 *Name:        kh_prf_encrypt_1_17_AB
 *
 *Description: KH_PRF to encrypt buf using key_point_poly_a and key_point_poly_b. 
 *             Assumes that the message is padded. The lower 17 and highest bits are
 *             zero before the addition of the product coefficient.
 *
 *Arguments:   - poly_60 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_60 *key_point_poly_b: pointer to the key mod Q_B
 *             - uint8_t *buf: pointer to the message
 *             - uint8_t *out: pointer to the ciphertext
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_encrypt_1_17_AB(poly_60 *key_point_poly_a, poly_60 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_120 product_poly;
    poly_120 noise_poly;

    int bytes_processed = 0;
    int bytes_written = 0;

    uint128_t sample_1, sample_2, sample_3, sample_4;
    while (bytes_processed < size)
    {
        create_product_point_AB(key_point_poly_a, key_point_poly_b, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_AB(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += COEFFS_PER_BLOCK)
        {
            sample_1 = 0;
            for (int j=0; j<12; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8*j));
            sample_1 |= (((uint128_t) buf[bytes_processed + 12]&63) << (8*12));
            sample_1 = (sample_1<<17) + NOISE_MAX;

            sample_2 = 0;
            for (int j=0; j<12; j++) sample_2 |= ((uint128_t) buf[bytes_processed + j+13] << (8*j));
            sample_2 |= (((uint128_t) buf[bytes_processed + 25]&63) << (8*12));
            sample_2 = (sample_2<<17) + NOISE_MAX;

            sample_3 = 0;
            for (int j=0; j<12; j++) sample_3 |= ((uint128_t) buf[bytes_processed + j+26] << (8*j));
            sample_3 |= (((uint128_t) buf[bytes_processed + 38]&63) << (8*12));
            sample_3 = (sample_3<<17) + NOISE_MAX;

            sample_4 = 0;
            for (int j=0; j<12; j++) sample_4 |= ((uint128_t) buf[bytes_processed + j+39] << (8*j));
            sample_4 |= (((uint128_t) buf[bytes_processed + 12]&192) << (8*12-6));
            sample_4 |= (((uint128_t) buf[bytes_processed + 25]&192) << (8*12-4));
            sample_4 |= (((uint128_t) buf[bytes_processed + 38]&192) << (8*12-2));
            sample_4 = (sample_4<<17) + NOISE_MAX;

            sample_1 = reduce_modq(sample_1 + (uint128_t) product_poly.coeffs[i] + (uint128_t) noise_poly.coeffs[i]);
            sample_2 = reduce_modq(sample_2 + (uint128_t) product_poly.coeffs[i + 1] + (uint128_t) noise_poly.coeffs[i + 1]);
            sample_3 = reduce_modq(sample_3 + (uint128_t) product_poly.coeffs[i + 2] + (uint128_t) noise_poly.coeffs[i + 2]);
            sample_4 = reduce_modq(sample_4 + (uint128_t) product_poly.coeffs[i + 3] + (uint128_t) noise_poly.coeffs[i + 3]);
            
            for (int j=0; j<15; j++) out[bytes_written + j     ] = (sample_1 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<15; j++) out[bytes_written + j + 15] = (sample_2 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<15; j++) out[bytes_written + j + 30] = (sample_3 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<15; j++) out[bytes_written + j + 45] = (sample_4 &((uint128_t)255ul << (8*j))) >> (8*j);

            bytes_processed += PAD_SIZE;
            bytes_written += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_decrypt_1_17_AB
 *
 *Description: KH_PRF to decrypt buf using key_point_poly_a and key_point_poly_b. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_60 *key_point_poly_a: pointer to the key mod Q_A
 *             - poly_60 *key_point_poly_b: pointer to the key mod Q_B
 *             - uint8_t *buf: pointer to the ciphertext
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int kh_prf_decrypt_1_17_AB(poly_60 *key_point_poly_a, poly_60 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_120 product_poly;
    poly_120 noise_poly;

    int bytes_processed = 0;
    int bytes_written = 0;

    uint128_t sample_1, sample_2, sample_3, sample_4;
    while (bytes_processed < size)
    {
        create_product_point_AB(key_point_poly_a, key_point_poly_b, &product_poly, (unsigned char *) &point_seed);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += COEFFS_PER_BLOCK)
        {
            sample_1 = 0;
            sample_2 = 0;
            sample_3 = 0;
            sample_4 = 0;

            for (int j=0; j<15; j++) {
              sample_1 |= ((uint128_t)buf[bytes_processed + j] << (8*j));
              sample_2 |= ((uint128_t)buf[bytes_processed + j + 15] << (8*j));
              sample_3 |= ((uint128_t)buf[bytes_processed + j + 30] << (8*j));
              sample_4 |= ((uint128_t)buf[bytes_processed + j + 45] << (8*j));
            }

            sample_1 = reduce_modq(sample_1 + (uint128_t)Q_AB - (uint128_t) (product_poly.coeffs[i]));
            sample_2 = reduce_modq(sample_2 + (uint128_t)Q_AB - (uint128_t) (product_poly.coeffs[i + 1]));
            sample_3 = reduce_modq(sample_3 + (uint128_t)Q_AB - (uint128_t) (product_poly.coeffs[i + 2]));
            sample_4 = reduce_modq(sample_4 + (uint128_t)Q_AB - (uint128_t) (product_poly.coeffs[i + 3]));

            sample_1 = sample_1>> 17;
            sample_2 = sample_2>> 17;
            sample_3 = sample_3>> 17;
            sample_4 = sample_4>> 17;
            

            for (int j=0; j<12; j++) {
              out[bytes_written + j] = (sample_1 &((uint128_t)255ul << (8*j))) >> (8*j);
              out[bytes_written + j + 13] = (sample_2 &((uint128_t)255ul << (8*j))) >> (8*j);
              out[bytes_written + j + 26] = (sample_3 &((uint128_t)255ul << (8*j))) >> (8*j);
              out[bytes_written + j + 39] = (sample_4 &((uint128_t)255ul << (8*j))) >> (8*j);
            }
            out[bytes_written + 12] = ((sample_1 >> (8*12)) | ((sample_4 >> (8*12-6)&192))); // should only get &63 
            out[bytes_written + 25] = ((sample_2 >> (8*12)) | ((sample_4 >> (8*12-4)&192))); ; // should only get &63 
            out[bytes_written + 38] = ((sample_3 >> (8*12)) | ((sample_4 >> (8*12-2)&192))); ; // should only get &63 

            

            bytes_processed += SAMPLE_BLOCK_SIZE;
            bytes_written += PAD_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_re_encrypt_1_17_AB
 *
 *Description: KH_PRF to re_encrypt buf using key_point_poly_a and key_point_poly_b. 
 *             Assumes that the message is padded.
 *
 *Arguments:   - poly_60 *key_point_poly_a: pointer to the delta of the new and old key mod Q_A
 *             - poly_60 *key_point_poly_b: pointer to the delta of the new and old key mod Q_B
 *             - uint8_t *buf: pointer to the old ciphertext
 *             - uint8_t *out: pointer to the new ciphertext
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     The length of the message in bytes.
 **************************************************/
int kh_prf_re_encrypt_1_17_AB(poly_60 *key_point_poly_a, poly_60 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_120 product_poly;
    poly_120 noise_poly;

    int bytes_processed = 0;

    uint128_t sample_1, sample_2, sample_3, sample_4;
    while (bytes_processed < size)
    {
        create_product_point_AB(key_point_poly_a, key_point_poly_b, &product_poly, (unsigned char *) &point_seed);
        poly_uniform_ref_noise_seeds_pseudo_AB(&noise_poly, (unsigned char *) &key_point_poly_a);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += COEFFS_PER_BLOCK)
        {
            sample_1 = 0;
            sample_2 = 0;
            sample_3 = 0;
            sample_4 = 0;
            for (int j=0; j<15; j++) {
              sample_1 |= ((uint128_t)buf[bytes_processed + j] << (8*j));
              sample_2 |= ((uint128_t)buf[bytes_processed + j + 15] << (8*j));
              sample_3 |= ((uint128_t)buf[bytes_processed + j + 30] << (8*j));
              sample_4 |= ((uint128_t)buf[bytes_processed + j + 45] << (8*j));
            }

            sample_1 = reduce_modq(sample_1 + (uint128_t) product_poly.coeffs[i] + (uint128_t) noise_poly.coeffs[i]);
            sample_2 = reduce_modq(sample_2 + (uint128_t) product_poly.coeffs[i + 1] + (uint128_t) noise_poly.coeffs[i + 1]);
            sample_3 = reduce_modq(sample_3 + (uint128_t) product_poly.coeffs[i + 2] + (uint128_t) noise_poly.coeffs[i + 2]);
            sample_4 = reduce_modq(sample_4 + (uint128_t) product_poly.coeffs[i + 3] + (uint128_t) noise_poly.coeffs[i + 3]);

            for (int j=0; j<15; j++) out[bytes_processed + j     ] = (sample_1 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<15; j++) out[bytes_processed + j + 15] = (sample_2 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<15; j++) out[bytes_processed + j + 30] = (sample_3 &((uint128_t)255ul << (8*j))) >> (8*j);
            for (int j=0; j<15; j++) out[bytes_processed + j + 45] = (sample_4 &((uint128_t)255ul << (8*j))) >> (8*j);

            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_processed;
}