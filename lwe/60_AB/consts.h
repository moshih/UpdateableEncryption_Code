#include <stdint.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#define addition_buf 128

#define IV_LEN 16
#define TAG_LEN 16
#define AE_KEY_LEN 16

#define POLY_SIZE 4096
#define NEWHOPE_SYMBYTES 32   /* size of shared key, seeds/coins, and hashes */
#define SHAKE128_RATE 168
#define P_16_BLOCK 65535

#define NEWHOPE_N 4096

typedef struct{
  int64_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_60;

typedef struct{
  int128_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_120;

// 2^60-1
#define half_block 1152921504606846975
// 2^40
#define block_40 1099511627775
#define AND_BLOCK (__int128)half_block + ((__int128)half_block<<60)

#define QA 1152921504606830593
#define QINV_S64_A 17365884561455595521U

#define QB 1152921504606748673
#define QINV_S64_B 949987710173185

#define QA_INV_B 230570227172514203
#define QB_INV_A 922351277434300007

#define QA_QA_INV_B_LOW 691738829337352603
#define QA_QA_INV_B_HIGH 230570227172510926
#define QA_QA_INV_B (__int128)QA_QA_INV_B_LOW + ((__int128)QA_QA_INV_B_HIGH<<60)
#define QB_QB_INV_A_LOW 461182676879992423
#define QB_QB_INV_A_HIGH 922351277434221363
#define QB_QB_INV_A (__int128)QB_QB_INV_A_LOW + ((__int128)QB_QB_INV_A_HIGH<<60)

#define TWO_64_2_A 68711088384
#define TWO_64_2_B 2473850831104

#define MODP_LOW_40 1097901129727
#define MODP_HIGH_40 120256987135
#define MODP (int128_t)MODP_LOW_40+((int128_t)MODP_HIGH_40<<40)

#define Q_AB_LOW 1610498049
#define Q_AB_HIGH 1152921504606732290

#define BLOCK_60 1152921504606846975

#define Q_AB (int128_t)Q_AB_LOW+((int128_t)Q_AB_HIGH<<60)

#define BLOCK_120 (int128_t)BLOCK_60+((int128_t)BLOCK_60<<60)

#define BARRETT_REDUCE_FACTOR 122

#define NOISE_MAX_BYTES_AB 3
#define NOISE_MAX 704
#define NOISE_MAX_FACTOR 5
#define NOISE_MULT_MAX (NOISE_MAX+1)*NOISE_MAX_FACTOR

#define PAD_SIZE 51
#define SAMPLE_BLOCK_SIZE 60
#define COEFFS_PER_BLOCK 4
#define BLOCK_SIZE NEWHOPE_N/COEFFS_PER_BLOCK*SAMPLE_BLOCK_SIZE

int pad_array(int8_t *buf, int size);
int unpad_array(int8_t *buf, int size);