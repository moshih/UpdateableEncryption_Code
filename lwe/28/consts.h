#include <stdint.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#define addition_buf 128

#define IV_LEN 16
#define TAG_LEN 16
#define AE_KEY_LEN 16

#define PAD_SIZE 3

#define POLY_SIZE 4096
#define NEWHOPE_SYMBYTES 32   /* size of shared key, seeds/coins, and hashes */
#define SHAKE128_RATE 168
#define P_16_BLOCK 65535

#define NEWHOPE_N 1024
#define SAMPLE_BLOCK_SIZE 7
#define BLOCK_SIZE NEWHOPE_N/2*SAMPLE_BLOCK_SIZE

typedef struct{ 
  int32_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_28;

// 2^28-1
#define AND_BLOCK 268435455

#define Q MODULO
#define MONT 409584 // 2^32 % Q
#define QINV_S64 1460691969  // q^(-1) mod 2^32
#define QINV_S32 QINV_S64  // q^(-1) mod 2^32

#define BARRETT_REDUCE_FACTOR 58
#define ZETA_INV_FINAL 193449472 //zeta first is 409584

#define NOISE_MAX 352
#define NOISE_MAX_FACTOR 11
#define NOISE_MULT_MAX (NOISE_MAX+1)*NOISE_MAX_FACTOR

#define BARRETT_REDUCE_V 1073844230

int pad_array(int8_t *buf, int size);
int unpad_array(int8_t *buf, int size);