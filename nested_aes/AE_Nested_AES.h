#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <time.h>

#include <openssl/rand.h>

#define KEY_LEN 16
#define IV_LEN 16
#define TAG_LEN 16
#define SEED_LEN 16

typedef struct AE_key AE_key;
typedef struct AE_ctx_header AE_ctx_header;
typedef struct ct_hat_data ct_hat_data;
typedef struct ct_hat_data_en ct_hat_data_en;
typedef struct AE_ctx_len AE_ctx_len;
typedef struct delta_token_data delta_token_data;

struct AE_key
{
	uint8_t key[KEY_LEN];
	int k_t;
};

struct AE_ctx_header
{
	uint8_t iv[IV_LEN]; // this value should be random
	uint8_t tag[TAG_LEN]; // set by AES GCM
};

struct AE_ctx_len
{
	int ctx_len;
	int ctx_hat_len;
};

// rho is the max size of an authenticated encryption key
// nu is the additive overhead incurred by the encryption algorithm
#define RHO KEY_LEN
#define NU 2*sizeof(AE_ctx_header)

struct ct_hat_data
{
	uint8_t prg_seed[SEED_LEN];
	uint8_t payload_key[KEY_LEN];
	uint8_t history_key[KEY_LEN];
	int ct_payload_length;
};

// holds the authenticated encryption of ct_hat_data
struct ct_hat_data_en
{
	AE_ctx_header header;
	uint8_t data[sizeof(ct_hat_data)];
};

struct delta_token_data
{
	AE_ctx_header ct_hat_data_header;
	ct_hat_data ct_hat;
	AE_ctx_header ct_hat_history_header;
	uint8_t ct_hat_history[2*KEY_LEN];
	int length;
	uint8_t key_ae[KEY_LEN];
	uint8_t prg_seed[SEED_LEN];
};

void AE_KeyGen(AE_key* ae_key, int t);
int AE_Encrypt(AE_key* ae_key, uint8_t* message, ct_hat_data_en* ciphertext_hat, uint8_t* ciphertext, int length);
void AE_Decrypt(AE_key* ae_key, ct_hat_data_en* ciphertext_hat, uint8_t* ciphertext, uint8_t* message, int ctx_length);
int AE_ReKeyGen(AE_key* ae_key1, AE_key* ae_key2, ct_hat_data_en* ciphertext_hat, delta_token_data* delta);
int AE_ReEncrypt(delta_token_data* delta, ct_hat_data_en* ciphertext_hat1, uint8_t* ciphertext1, ct_hat_data_en* ciphertext_hat2, uint8_t* ciphertext2,  int ctx_length);