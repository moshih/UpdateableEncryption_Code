#include <stdint.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#define addition_buf 128

#define IV_LEN 16
#define TAG_LEN 16
#define AE_KEY_LEN 16

#define PAD_SIZE 27

#define POLY_SIZE 4096
#define NEWHOPE_SYMBYTES 32   /* size of shared key, seeds/coins, and hashes */
#define SHAKE128_RATE 168
#define P_16_BLOCK 65535

#define NEWHOPE_N 4096
#define SAMPLE_BLOCK_SIZE 16
#define BLOCK_SIZE NEWHOPE_N*SAMPLE_BLOCK_SIZE

typedef struct{
  uint128_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_128;

// 2^60-1
#define half_block 18446744073709551615U
#define AND_BLOCK (uint128_t)half_block + ((uint128_t)half_block<<64)

#define MODP 102399

#define Q_LOW 18446744073709449217U
#define Q_HIGH 18446744073709551615U

#define BLOCK_64 18446744073709551615U

#define Q (uint128_t)Q_LOW+((uint128_t)Q_HIGH<<64)

#define BLOCK_128 (uint128_t)BLOCK_64+((uint128_t)BLOCK_64<<64)

#define MONT 102399 // 2^128 % Q

#define qinv_lower 8798678444595327588U
#define qinv_higher 8744094284063203018U
#define qinv (uint128_t)qinv_lower+((uint128_t)qinv_higher<<64)

// Bounds on the error
#define NOISE_MAX 704
#define NOISE_MAX_FACTOR 92
#define NOISE_MULT_MAX (NOISE_MAX+1)*NOISE_MAX_FACTOR

void create_zeta_array(uint64_t zetas_lower[2048], uint64_t zetas_higher[2048], uint128_t zetas[2048]);

int sodium_compare(const uint128_t a, const uint128_t b);
uint128_t a_greater_b(const uint128_t a, const uint128_t b);
uint128_t a_less_b(const uint128_t a, const uint128_t b);
uint128_t addModP(uint128_t in1, uint128_t in2);
uint128_t subModP(uint128_t in1, uint128_t in2);
uint128_t mulitply_mod(uint128_t input_a, uint128_t input_b);

int pad_array(int8_t *buf, int size);
int unpad_array(int8_t *buf, int size);
