#include "crypto_algorithms.h"
#include "fips202.h"

extern uint64_t zetas_lower[2048];
extern uint64_t zetas_higher[2048];
extern uint64_t zetas_inv_lower[2048];
extern uint64_t zetas_inv_higher[2048];

/*************************************************
 *Name:        poly_uniform_ref_poly_128
 *
 *Description: Takes in a 32 bytes seed, generates a poly_128 with shake128 
 *             uniformly random elements in mod Q.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_128 *a: pointer to the poly_128 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_poly_128(poly_128 *a, const unsigned char *seed)
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

    while (coeffs_written != NEWHOPE_N)
    {
        if (iteration == 65536) printf("ERROR: poly_uniform_ref_poly_60: iteration hit its limit\n");

        extseed[NEWHOPE_SYMBYTES] = iteration; /*domain-separate the 16 independent calls */

        if (extseed[NEWHOPE_SYMBYTES] == 0) extseed[NEWHOPE_SYMBYTES + 1]++;

        // Run the hash function
        shake128_absorb(state, extseed, NEWHOPE_SYMBYTES + 2);
        shake128_squeezeblocks(buf, 1, state);

        uint128_t leftover = 0;

        // Translate hash output to polynomial
        for (j = 0; j < SHAKE128_RATE - SAMPLE_BLOCK_SIZE && coeffs_written < NEWHOPE_N; j += SAMPLE_BLOCK_SIZE)
        {

            uint128_t sample_1 = 0;
            for (int k = 0; k < SAMPLE_BLOCK_SIZE; k++) sample_1 |= ((uint128_t) buf[j + k] << (8 *k));

            // Check if block of hash output is in range
            if (sample_1 < Q)
            {
                a->coeffs[coeffs_written] = sample_1;
                coeffs_written++;
            }
        }

        // If we have enough coefficients, then return
        if (coeffs_written == NEWHOPE_N) return;

        // Some kind of clean-up before looping again
        if (j % 2 == 0)
            for (int k = 0; k < (SAMPLE_BLOCK_SIZE >> 1); k++) leftover |= ((uint128_t) buf[128 + k] << (8 *k));
        if (j % 2 == 1)
        {
            for (int k = 0; k < (SAMPLE_BLOCK_SIZE >> 1); k++) leftover |= ((uint128_t) buf[128 + k] << (8 *k + 64));

            if (leftover < Q)
            {
                a->coeffs[coeffs_written] = leftover;
                coeffs_written++;
            }
            leftover = 0;
        }
        iteration++;
    }
}

/*************************************************
 *Name:        poly_uniform_ref_message
 *
 *Description: Computes the shake128 hash of a message (seed) given its size and outputs to a.       
               (Used for UAE Integrity, not for PRF evaluation)
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
 *Name:        poly_uniform_ref_noise_16_1_seeds_pseudo
 *
 *Description: Takes in a 32 bytes seed, generates a poly_128 with shake128 
 *             uniformly random elements in mod Q. Differs than poly_uniform_ref_poly_128
 *             because it is used to generate the noise poly so the input extseed is different.
 *             Note: It can only go through 65536 iterations before the seed is repeated.          
 *
 *Arguments:   - poly_128 *a: pointer to the poly_128 to be generated
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void poly_uniform_ref_noise_16_1_seeds_pseudo(poly_128 *a, const unsigned char *seed)
{
    uint64_t state[25];
    uint8_t buf[SHAKE128_RATE];
    uint8_t extseed[(2 *NEWHOPE_SYMBYTES + 2)];
    int i, j;

    for (i = 0; i < 2 *NEWHOPE_SYMBYTES + 2; i++) extseed[i] = 0;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
        extseed[i] = seed[i];

    int coeffs_written = 0;
    int iteration = 0;

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

        // Run the hash function
        shake128_absorb(state, extseed, 2 *NEWHOPE_SYMBYTES + 2);
        shake128_squeezeblocks(buf, 1, state);

        // Rejection sampling
        for (j = 0; j < SHAKE128_RATE - 2 && coeffs_written < NEWHOPE_N; j += 2)
        {

            uint128_t sample_1 = ((uint128_t) buf[j] | ((uint128_t) buf[j + 1] << 8));

            // Range check
            if (sample_1 < NOISE_MULT_MAX)
            {
                a->coeffs[coeffs_written] = sample_1 / NOISE_MAX_FACTOR;
                coeffs_written++;
            }
        }

        iteration++;
    }
}

/*************************************************
 *Name:        create_product_point
 *
 *Description: Takes in a poly_128 key_point_poly and seed of a poly_128, point_seed,
 *             generates the second poly_128 from point_seed, multiplies them as if 
 *             they are in the NTT domain, then computes the inverse NTT of the product.
 *
 *Arguments:   - poly_128 *key_point_poly: pointer to the poly_128 input
 *             - poly_128 *product_point_poly: pointer to the poly_128 product
 *             - const unsigned char *seed: pointer to the seed input
 *
 *Returns:     None
 **************************************************/
void create_product_point(poly_128 *key_point_poly, poly_128 *product_point_poly, unsigned char *point_seed, const uint128_t *zetas, uint128_t *zetas_inv)
{
    int i;

    for (i = 0; i < NEWHOPE_SYMBYTES; i++)
    {
        point_seed[i] += 1;
        if (point_seed[i] != 0) break;
    }

    poly_128 point_poly;

    poly_uniform_ref_poly_128(&point_poly, point_seed);                   // Change IV (ctr) to polynomial in NTT form

    poly_basemul(product_point_poly, key_point_poly, &point_poly, zetas); // Multiply s(x)*H(iv) in NTT form
    poly_invntt(product_point_poly, zetas_inv);                           // Convert s(x)*H(iv) to coefficient form
}

/*************************************************
 *Name:        kh_prf_encrypt
 *
 *Description: KH_PRF to encrypt but using key_point_poly.
 *             Assumes that the message has been padded to be a multiple of 16
 *
 *Arguments:   - poly_128 *key_point_poly: pointer to the poly_128 key
 *             - uint8_t *buf: pointer to the message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     None
 **************************************************/
void kh_prf_encrypt(poly_128 *key_point_poly, uint8_t *buf, unsigned int size)
{

    uint128_t zetas[2048];
    uint128_t zetas_inv[2048];

    create_zeta_array(zetas_lower, zetas_higher, zetas);
    create_zeta_array(zetas_inv_lower, zetas_inv_higher, zetas_inv);

    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 }; 

    point_seed[0] = 1;
    poly_128 product_poly;
    poly_128 noise_poly;

    uint128_t guassian_output;

    int bytes_processed = 0;
    while (bytes_processed < size)
    {
        // Create noiseless LWE sample H(iv)*s(x)
        create_product_point(key_point_poly, &product_poly, (unsigned char *) &point_seed, zetas, zetas_inv); 

        // Create noise polynomial e(x)
        poly_uniform_ref_noise_16_1_seeds_pseudo(&noise_poly, (unsigned char *) &key_point_poly);  

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i++)
        {

            uint128_t sample_1 = 0;

            for (int j = 0; j < SAMPLE_BLOCK_SIZE; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8 *j));

            sample_1 = addModP(addModP(sample_1, (uint128_t) product_poly.coeffs[i]), subModP((uint128_t) noise_poly.coeffs[i], NOISE_MAX / 2)); 

            for (int j = 0; j < SAMPLE_BLOCK_SIZE; j++) buf[bytes_processed + j] = (sample_1 &((uint128_t) 255ul << (8 *j))) >> (8 *j);

            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
}

/*************************************************
 *Name:        kh_prf_re_encrypt
 *
 *Description: KH_PRF to re_encrypt buf using key_point_poly_2.
 *
 *Arguments:   - poly_128 *key_point_poly_1: pointer to the original poly_128 key
 *             - poly_128 *key_point_poly_2: pointer to the new poly_128 key
 *             - uint8_t *test_array: pointer to the ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     None
 **************************************************/
void kh_prf_re_encrypt(poly_128 *key_point_poly_1, poly_128 *key_point_poly_2, uint8_t *test_array, unsigned int size)
{
    poly_128 diff_poly;

    for (int i = 0; i < NEWHOPE_N; i++) diff_poly.coeffs[i] = subModP(key_point_poly_2->coeffs[i], key_point_poly_1->coeffs[i]);

    kh_prf_encrypt(&diff_poly, test_array, size);
}

/*************************************************
 *Name:        lwe_gen_key
 *
 *Description: Generated a random poly_128 with no input.
 *
 *Arguments:   - poly_128 *key_point_poly: pointer to the poly_128 generated
 *
 *Returns:     None
 **************************************************/
void lwe_gen_key(poly_128 *key_point_poly)
{
    uint8_t key_seed[NEWHOPE_SYMBYTES];
    RAND_bytes(key_seed, NEWHOPE_SYMBYTES);
    poly_uniform_ref_poly_128(key_point_poly, key_seed);
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
 *Name:        kh_prf_encrypt_2_5
 *
 *Description: KH_PRF to encrypt buf using key_point_poly. Similar to kh_prf_encrypt
 *             but the bottom 2.5 bytes of each coefficient is empty.
 *             Assumes that the message has been padded to be a multiple of 27.
 *
 *Arguments:   - poly_128 *key_point_poly: pointer to the poly_128 key
 *             - uint8_t *buf: pointer to the message
 *             - unsigned int size: size of message in bytes
 *
 *Returns:     None
 **************************************************/
int kh_prf_encrypt_2_5(poly_128 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int128_t zetas[2048];
    int128_t zetas_inv[2048];

    create_zeta_array(zetas_lower, zetas_higher, zetas);
    create_zeta_array(zetas_inv_lower, zetas_inv_higher, zetas_inv);

    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_128 product_poly;
    poly_128 noise_poly;

    uint128_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;
    while (bytes_processed < size)
    {
        // Create noiseless LWE sample H(iv)*s(x)
        create_product_point(key_point_poly, &product_poly, (unsigned char *) &point_seed, zetas, zetas_inv);

        // Create noise polynomial e(x)
        poly_uniform_ref_noise_16_1_seeds_pseudo(&noise_poly, (unsigned char *) &key_point_poly);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {

            uint128_t sample_1 = NOISE_MAX;
            uint128_t sample_2 = NOISE_MAX;

            sample_1 |= ((uint128_t)(buf[bytes_processed] &15ul) << (8 * 2 + 4));
            sample_2 |= ((uint128_t)(buf[bytes_processed] &240ul) << (8 *2));
            for (int j = 3; j < SAMPLE_BLOCK_SIZE; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j - 2] << (8 *j));
            for (int j = 3; j < SAMPLE_BLOCK_SIZE; j++) sample_2 |= ((uint128_t) buf[bytes_processed + j - 3 + 14] << (8 *j));

            // Compute H(x)*s(x)+e(x)
            sample_1 = addModP(addModP(sample_1, (uint128_t) product_poly.coeffs[i]), (uint128_t) noise_poly.coeffs[i]);
            sample_2 = addModP(addModP(sample_2, (uint128_t) product_poly.coeffs[i + 1]), (uint128_t) noise_poly.coeffs[i + 1]);

            for (int j = 0; j < SAMPLE_BLOCK_SIZE; j++) out[bytes_written + j] = (sample_1 &((uint128_t) 255ul << (8 *j))) >> (8 *j);
            for (int j = 0; j < SAMPLE_BLOCK_SIZE; j++) out[SAMPLE_BLOCK_SIZE + bytes_written + j] = (sample_2 &((uint128_t) 255ul << (8 *j))) >> (8 *j);

            bytes_processed += PAD_SIZE;
            bytes_written += 2 * SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_written;
}


/*************************************************
 *Name:        kh_prf_decrypt_2_5
 *
 *Description: KH_PRF to decrypt buf using key_point_poly. Similar to kh_prf_decrypt
 *             but the bottom 2.5 bytes of each coefficient is empty.
 *
 *Arguments:   - poly_128 *key_point_poly: pointer to the poly_128 key
 *             - uint8_t *buf: pointer to the ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     The length of the decrypted message in bytes.
 **************************************************/
int kh_prf_decrypt_2_5(poly_128 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int128_t zetas[2048];
    int128_t zetas_inv[2048];

    create_zeta_array(zetas_lower, zetas_higher, zetas);
    create_zeta_array(zetas_inv_lower, zetas_inv_higher, zetas_inv);

    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_128 product_poly;

    uint128_t guassian_output;

    int bytes_processed = 0;
    int bytes_written = 0;
    while (bytes_processed < size)
    {
        create_product_point(key_point_poly, &product_poly, (unsigned char *) &point_seed, zetas, zetas_inv);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i += 2)
        {

            uint128_t sample_1 = 0;
            uint128_t sample_2 = 0;

            for (int j = 0; j < SAMPLE_BLOCK_SIZE; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8 *j));
            for (int j = 0; j < SAMPLE_BLOCK_SIZE; j++) sample_2 |= ((uint128_t) buf[SAMPLE_BLOCK_SIZE + bytes_processed + j] << (8 *j));

            sample_1 = subModP(sample_1, (uint128_t) product_poly.coeffs[i]);
            sample_2 = subModP(sample_2, (uint128_t) product_poly.coeffs[i + 1]);

            for (int j = 3; j < SAMPLE_BLOCK_SIZE; j++) out[bytes_written + j - 2] = (sample_1 &((uint128_t) 255ul << (8 *j))) >> (8 *j);
            for (int j = 3; j < SAMPLE_BLOCK_SIZE; j++) out[bytes_written + j - 3 + 14] = (sample_2 &((uint128_t) 255ul << (8 *j))) >> (8 *j);
            out[bytes_written] = (sample_1 >> (8 * 2 + 4)) &15ul;
            out[bytes_written] |= (sample_2 >> (8 *2)) &240ul;

            bytes_processed += 2 * SAMPLE_BLOCK_SIZE;
            bytes_written += PAD_SIZE;
        }
    }
    return bytes_written;
}

/*************************************************
 *Name:        kh_prf_re_encrypt_2_5
 *
 *Description: KH_PRF to re_encrypt buf using key_point_poly. Simliar to
 *             kh_prf_re_encrypt but set eh the bottom 2.5 bytes of each coefficient
 *             to be empty.
 *
 *Arguments:   - poly_128 *key_point_poly: pointer to the delta of the new and old key
 *             - uint8_t *buf: pointer to the input ciphertext
 *             - uint8_t *output: pointer to the output ciphertext
 *             - unsigned int size: size of ciphertext in bytes
 *
 *Returns:     The length of the ciphertext in bytes.
 **************************************************/
int kh_prf_re_encrypt_2_5(poly_128 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size)
{
    int128_t zetas[2048];
    int128_t zetas_inv[2048];

    create_zeta_array(zetas_lower, zetas_higher, zetas);
    create_zeta_array(zetas_inv_lower, zetas_inv_higher, zetas_inv);

    int i;
    unsigned char point_seed[NEWHOPE_SYMBYTES] = { 0 };

    point_seed[0] = 1;
    poly_128 product_poly;
    poly_128 noise_poly;

    uint128_t guassian_output;

    int bytes_processed = 0;
    while (bytes_processed < size)
    {
        // Generate PRF evaluation
        create_product_point(key_point_poly, &product_poly, (unsigned char *) &point_seed, zetas, zetas_inv);
        poly_uniform_ref_noise_16_1_seeds_pseudo(&noise_poly, (unsigned char *) &key_point_poly);

        for (i = 0; i < NEWHOPE_N && bytes_processed < size; i++)
        {

            uint128_t sample_1 = NOISE_MAX;

            for (int j = 0; j < SAMPLE_BLOCK_SIZE; j++) sample_1 |= ((uint128_t) buf[bytes_processed + j] << (8 *j));

            sample_1 = addModP(addModP(sample_1, (uint128_t) product_poly.coeffs[i]), (uint128_t) noise_poly.coeffs[i]);

            for (int j = 0; j < SAMPLE_BLOCK_SIZE; j++) out[bytes_processed + j] = (sample_1 &((uint128_t) 255ul << (8 *j))) >> (8 *j);

            bytes_processed += SAMPLE_BLOCK_SIZE;
        }
    }
    return bytes_processed;
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

    int output_len = kh_prf_encrypt_2_5(&data_header.poly_key, message, ciphertext, padded_size);

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

    int output_len = kh_prf_decrypt_2_5(&data_header.poly_key, ciphertext, decrypted_message, size);
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

    poly_128 poly_key1;
    memcpy(&poly_key1, &data_header.poly_key, sizeof(poly_128));
    lwe_gen_key(&data_header.poly_key);

    for (int i = 0; i < NEWHOPE_N; i++) delta->poly_key.coeffs[i] = subModP((uint128_t) data_header.poly_key.coeffs[i], (uint128_t) poly_key1.coeffs[i]);

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
    int re_encrypt_length = kh_prf_re_encrypt_2_5(&delta->poly_key, ciphertext1, ciphertext2, size);

    return re_encrypt_length;
}
