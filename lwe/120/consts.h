#include <stdint.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#define addition_buf 128

#define IV_LEN 16
#define TAG_LEN 16
#define AE_KEY_LEN 16

#define PAD_SIZE 25

#define POLY_SIZE 4096
#define NEWHOPE_SYMBYTES 32   /* size of shared key, seeds/coins, and hashes */
#define SHAKE128_RATE 168
#define P_16_BLOCK 65535

#define NEWHOPE_N 4096
#define SAMPLE_BLOCK_SIZE 15
#define BLOCK_SIZE NEWHOPE_N*SAMPLE_BLOCK_SIZE

typedef struct{
  int128_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_120;

// 2^60-1
#define half_block 1152921504606846975
#define AND_BLOCK (__int128)half_block + ((__int128)half_block<<60)

#define MODP 102399

#define Q_LOW 1152921504606744577
#define Q_HIGH 1152921504606846975

#define BLOCK_60 1152921504606846975

#define Q (int128_t)Q_LOW+((int128_t)Q_HIGH<<60)

#define BLOCK_120 (int128_t)BLOCK_60+((int128_t)BLOCK_60<<60)

#define MAX ((uint128_t)1<<127)-1
#define MAX_MODQ 13107071

#define MONT 26214144 // 2^128 % Q

#define qinv_lower 754945778053431109
#define qinv_higher 551009492381320684
#define qinv (int128_t)qinv_lower+((int128_t)qinv_higher<<60)

#define NOISE_MAX 704
#define NOISE_MAX_FACTOR 92
#define NOISE_MULT_MAX (NOISE_MAX+1)*NOISE_MAX_FACTOR

void create_zeta_array(int64_t zetas_lower[2048], int64_t zetas_higher[2048], int128_t zetas[2048]);
int128_t mulitply_mod(int128_t input_a, int128_t input_b);

int pad_array(int8_t *buf, int size);
int unpad_array(int8_t *buf, int size);