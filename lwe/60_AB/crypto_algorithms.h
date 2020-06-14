#include <stdio.h>
#include <stdint.h>

#include <string.h>
#include <openssl/rand.h>

#include "aes_gcm.h"
#include "ntt_A.h"
#include "ntt_B.h"

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
  poly_60 poly_keya;
  poly_60 poly_keyb;
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
  poly_60 poly_keya;
  poly_60 poly_keyb;
};

void poly_uniform_ref_poly_60_AB(poly_60 *a, poly_60 *b, const unsigned char *seed);

void lwe_gen_key(poly_60 *key_point_polya, poly_60 *key_point_polyb);

void UAE_Keygen(int8_t *AE_key);
int UAE_Encrypt(int8_t *AE_key,uint8_t *message, UAE_lwe_ctx_header* ciphertext_hat, uint8_t* ciphertext, unsigned int size);
int UAE_Decrypt(int8_t *AE_key,uint8_t *decrypted_message, UAE_lwe_ctx_header* ciphertext_hat, uint8_t* ciphertext, unsigned int size);
int UAE_ReKeygen(int8_t *AE_key1,int8_t *AE_key2, UAE_lwe_ctx_header* ciphertext_hat, UAE_lwe_delta* delta);
int UAE_ReEncrypt(UAE_lwe_delta* delta, 
  UAE_lwe_ctx_header* ciphertext_hat1, uint8_t* ciphertext1, 
  UAE_lwe_ctx_header* ciphertext_hat2, uint8_t* ciphertext2, unsigned int size);

int128_t mulitply_mod_80(int128_t input_a);
int128_t mulitply_mod_120(int128_t input_a);
int128_t mulitply_mod_160(int128_t input_a);

int128_t mulitply_mod(int128_t input_a, int128_t input_b);

int128_t reduce_modq(int128_t input);

void poly_combine_120_AB(poly_60 *a, poly_60 *b, poly_120 *c);
void separate_120_AB(poly_60 *a, poly_60 *b, poly_120 *c);

void create_product_point_AB(poly_60 *key_a, poly_60 *key_b, poly_120 *product, unsigned char *point_seed);

void poly_uniform_ref_noise_seeds_pseudo_AB(poly_120 *a, const unsigned char *seed);

int kh_prf_encrypt_1_17_AB(poly_60 *key_point_poly_a, poly_60 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size);

int kh_prf_decrypt_1_17_AB(poly_60 *key_point_poly_a, poly_60 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size);

int kh_prf_re_encrypt_1_17_AB(poly_60 *key_point_poly_a, poly_60 *key_point_poly_b, uint8_t *buf, uint8_t *out, unsigned int size);