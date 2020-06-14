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
#define NEWHOPE_N_AVX 4608

#define PAD_SIZE 33
#define SAMPLE_BLOCK_SIZE 42
#define COEFFS_PER_BLOCK 4
#define BLOCK_SIZE NEWHOPE_N/COEFFS_PER_BLOCK*SAMPLE_BLOCK_SIZE

typedef struct{ 
  int32_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_28;

typedef struct{ 
  int128_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_84;

#define QA 268369921
#define QINV_S64_A 4026597377  // q^(-1) mod 2^32
#define QINV_S32_A QINV_S64_A  // q^(-1) mod 2^32

#define BARRETT_REDUCE_FACTOR  58 // floor(Log2[q])-1+32
#define ZETA_INV_FINAL_A 234938367 // Mod[PowerMod[512, -1, 268369921]*1048560*PowerMod[2, 32, 268369921], 268369921]

#define BARRETT_REDUCE_V_A 1074004029 //const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) Q + 1;

int pad_array(int8_t *buf, int size);
int unpad_array(int8_t *buf, int size);

#define QB 268361729
#define QINV_S64_B 872488961  // q^(-1) mod 2^32
#define QINV_S32_B QINV_S64_B  // q^(-1) mod 2^32
#define ZETA_INV_FINAL_B 109190142 // Mod[PowerMod[512, -1, 268369921]*1048560*PowerMod[2, 32, 268369921], 268369921]
#define BARRETT_REDUCE_V_B 1074036814 //const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) Q + 1;

// 268271617
#define QC 268271617
#define QINV_S64_C 805470209  // q^(-1) mod 2^32
#define QINV_S32_C QINV_S64_C  // q^(-1) mod 2^32
#define ZETA_INV_FINAL_C 102608884 // Mod[PowerMod[512, -1, 268369921]*1048560*PowerMod[2, 32, 268369921], 268369921]
#define BARRETT_REDUCE_V_C 1074397581 //const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) Q + 1;

// AB
#define Q_AB 72020216011153409
#define QINV_S64 10706299326180761601U

#define TWO_64 9568774854278912

#define QA_INV_B 268328970
#define QB_INV_A 32760

// TWO_64*QA*QA_INV_B
#define QB_QA_INV_B 43335945451206400
#define QB_QB_INV_A 38253045414225921

#define BARRETT_REDUCE_FACTOR_AB 118

#define TWO_64_3 45720068435305548
#define QAB_INV_C 154454454
#define QAB_QAB_INV_C_LOW 13742660129043646902U
#define QAB_QAB_INV_C_HIGH 603024
#define QAB_QAB_INV_C (int128_t)QAB_QAB_INV_C_LOW+((int128_t)QAB_QAB_INV_C_HIGH<<64)

#define QC_INV_AB 30555363093206604
#define QC_QC_INV_AB_LOW 12341234565047211596U
#define QC_QC_INV_AB_HIGH 444367
#define QC_QC_INV_AB (int128_t)QC_QC_INV_AB_LOW+((int128_t)QC_QC_INV_AB_HIGH<<64)

#define NOISE_MAX_BYTES 3
#define NOISE_MAX 704
#define NOISE_MAX_FACTOR 5
#define NOISE_MULT_MAX (NOISE_MAX+1)*NOISE_MAX_FACTOR

#define Q_ABC_LOW 7637150620381306881U
#define Q_ABC_HIGH 1047392
#define Q_ABC (int128_t)Q_ABC_LOW+((int128_t)Q_ABC_HIGH<<64)

// Mod[2^124,Q_ABC]
#define MODP_124_P_LOW_62 2973244382952544623
#define MODP_124_P_HIGH_22 316288
#define MODP_124_P (int128_t)MODP_124_P_LOW_62+((int128_t)MODP_124_P_HIGH_22<<62)

#define MODP_84_P_LOW_62 1586221416473468927
#define MODP_84_P_HIGH_22 4734
#define MODP_84_P (int128_t)MODP_84_P_LOW_62+((int128_t)MODP_84_P_HIGH_22<<62)

#define BLOCK_62 4611686018427387903

#define BLOCK_22 4194303
#define BLOCK_124 (int128_t)BLOCK_62+((int128_t)BLOCK_62<<62)
#define BLOCK_84 (uint128_t)BLOCK_62+((uint128_t)BLOCK_22<<62)

#define MESSAGE_BLOCK_SIZE 9984
#define C_MESSAGE_BLOCK_SIZE 10240