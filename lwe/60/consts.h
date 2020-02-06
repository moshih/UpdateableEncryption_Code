#include <stdint.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#define addition_buf 128

#define IV_LEN 16
#define TAG_LEN 16
#define AE_KEY_LEN 16

#define PAD_SIZE 11

#define POLY_SIZE 4096
#define NEWHOPE_SYMBYTES 32   /* size of shared key, seeds/coins, and hashes */
#define SHAKE128_RATE 168
#define P_16_BLOCK 65535

#define NEWHOPE_N 2048
#define SAMPLE_BLOCK_SIZE 15
#define BLOCK_SIZE NEWHOPE_N/2*SAMPLE_BLOCK_SIZE

typedef struct{
  int64_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_60;

// 2^60-1
#define AND_BLOCK 1152921504606846975

#define Q 1152921504606830593
#define MONT 262128 // 2^32 % Q
#define QINV_S64 -1080859512253956095

#define BARRETT_REDUCE_FACTOR 122
#define ZETA_INV_FINAL 864691128522223617

#define NOISE_MAX 498
#define NOISE_MAX_FACTOR 2
#define NOISE_MULT_MAX (NOISE_MAX+1)*NOISE_MAX_FACTOR

int pad_array(int8_t *buf, int size);
int unpad_array(int8_t *buf, int size);