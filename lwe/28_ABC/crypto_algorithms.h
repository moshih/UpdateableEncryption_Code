#include <stdio.h>
#include <stdint.h>

#include <string.h>
#include <openssl/rand.h>

#include "aes_gcm.h"

//#include "crypto_algorithms_268369921.h"
#include "ntt_268369921.h"
#include "ntt_268361729.h"
#include "ntt_268271617.h"

#include "fips202.h"
#include "fips202x4.h"

typedef struct AE_ctx_header AE_ctx_header;
typedef struct UAE_lwe_data_header UAE_lwe_data_header;
typedef struct UAE_lwe_ctx_header UAE_lwe_ctx_header;
typedef struct UAE_lwe_delta UAE_lwe_delta;

struct AE_ctx_header
{
  uint8_t iv[IV_LEN]; // this value should be random
  uint8_t tag[TAG_LEN]; // set by AES GCM
};

struct UAE_lwe_data_header
{
  poly_28 poly_keya;
  poly_28 poly_keyb;
  poly_28 poly_keyc;
  uint8_t hash[SHAKE128_RATE]; // set by AES GCM
};

struct UAE_lwe_ctx_header
{
  uint8_t iv[IV_LEN]; // this value should be random
  uint8_t tag[TAG_LEN]; // set by AES GCM
  uint8_t ctx[sizeof(UAE_lwe_data_header)]; // set by AES GCM
};

struct UAE_lwe_delta
{
  UAE_lwe_ctx_header ctx_header;
  poly_28 poly_keya;
  poly_28 poly_keyb;
  poly_28 poly_keyc;
};

int64_t montgomery_reduce_AB(__int128 a);

void poly_uniform_ref_poly_28_ABC(poly_28 *a, poly_28 *b, poly_28 *c, const unsigned char *seed);
void poly_uniform_ref_poly_28_ABC_avx(poly_28 *a, poly_28 *b, poly_28 *c, const unsigned char *seed);

void lwe_gen_key(poly_28 *key_point_polya, poly_28 *key_point_polyb, poly_28 *key_point_polyc);
void lwe_gen_key_avx(poly_28 *key_point_polya, poly_28 *key_point_polyb, poly_28 *key_point_polyc);

void UAE_Keygen(int8_t *AE_key);
int UAE_Encrypt(int8_t *AE_key, uint8_t *message, UAE_lwe_ctx_header *ciphertext_hat, uint8_t *ciphertext, unsigned int size);
int UAE_Encrypt_avx(int8_t *AE_key, uint8_t *message, UAE_lwe_ctx_header *ciphertext_hat, uint8_t *ciphertext, unsigned int size);
int UAE_Decrypt(int8_t *AE_key, uint8_t *decrypted_message, UAE_lwe_ctx_header *ciphertext_hat, uint8_t *ciphertext, unsigned int size);
int UAE_Decrypt_avx(int8_t *AE_key, uint8_t *decrypted_message, UAE_lwe_ctx_header *ciphertext_hat, uint8_t *ciphertext, unsigned int size);
int UAE_ReKeygen(int8_t *AE_key1, int8_t *AE_key2, UAE_lwe_ctx_header *ciphertext_hat, UAE_lwe_delta *delta);
int UAE_ReKeygen_avx(int8_t *AE_key1, int8_t *AE_key2, UAE_lwe_ctx_header *ciphertext_hat, UAE_lwe_delta *delta);
int UAE_ReEncrypt(UAE_lwe_delta *delta,
    UAE_lwe_ctx_header *ciphertext_hat1, uint8_t *ciphertext1,
    UAE_lwe_ctx_header *ciphertext_hat2, uint8_t *ciphertext2, unsigned int size);
int UAE_ReEncrypt_avx(UAE_lwe_delta *delta,
    UAE_lwe_ctx_header *ciphertext_hat1, uint8_t *ciphertext1,
    UAE_lwe_ctx_header *ciphertext_hat2, uint8_t *ciphertext2, unsigned int size);

int128_t mulitply_mod(int128_t input_a, int128_t input_b);

int128_t reduce_modq(int128_t input);

void poly_combine_84_ABC(poly_28 *a, poly_28 *b, poly_28 *c, poly_84 *d);

void create_product_point_ABC(poly_28 *key_a, poly_28 *key_b, poly_28 *key_c, poly_84 *product, unsigned char *point_seed);
void create_product_point_ABC_avx(poly_28 *key_a, poly_28 *key_b, poly_28 *key_c, poly_84 *product, unsigned char *point_seed);

void poly_uniform_ref_noise_seeds_pseudo_ABC(poly_84 *a, const unsigned char *seed);
void poly_uniform_ref_noise_seeds_pseudo_ABC_avx(poly_84 *a, const unsigned char *seed);

int kh_prf_encrypt_1_17_ABC(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size);
int kh_prf_decrypt_1_17_ABC(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size);
int kh_prf_re_encrypt_1_17_ABC(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size);

int kh_prf_encrypt_1_17_ABC_avx(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size);
int kh_prf_decrypt_1_17_ABC_avx(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size);
int kh_prf_re_encrypt_1_17_ABC_avx(poly_28 *key_point_poly_a, poly_28 *key_point_poly_b, poly_28 *key_point_poly_c, uint8_t *buf, uint8_t *out, unsigned int size);