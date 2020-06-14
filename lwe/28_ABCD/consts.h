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

typedef struct{ 
  int32_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_28;

typedef struct{ 
  int128_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_112;

#define QA 268369921
#define QINV_S64_A 4026597377  // q^(-1) mod 2^32
#define QINV_S32_A QINV_S64_A  // q^(-1) mod 2^32

#define BARRETT_REDUCE_FACTOR  58 // floor(Log2[q])-1+32
#define ZETA_INV_FINAL_A 234938367 // Mod[PowerMod[512, -1, 268369921]*1048560*PowerMod[2, 32, 268369921], 268369921]

#define NOISE_MAX_BYTES 3
#define NOISE_MAX 704
#define NOISE_MAX_FACTOR 5
#define NOISE_MULT_MAX (NOISE_MAX+1)*NOISE_MAX_FACTOR

#define BARRETT_REDUCE_V_A 1074004029 //const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) Q + 1;

int pad_array(int8_t *buf, int size);
int unpad_array(int8_t *buf, int size);

#define QB 268361729
#define QINV_S64_B 872488961  // q^(-1) mod 2^32
#define QINV_S32_B QINV_S64_B  // q^(-1) mod 2^32
#define ZETA_INV_FINAL_B 109190142 // Mod[PowerMod[512, -1, 268369921]*1048560*PowerMod[2, 32, 268369921], 268369921]
#define BARRETT_REDUCE_V_B 1074036814 //const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) Q + 1;

#define QC 268271617
#define QINV_S64_C 805470209  // q^(-1) mod 2^32
#define QINV_S32_C QINV_S64_C  // q^(-1) mod 2^32
#define ZETA_INV_FINAL_C 102608884 // Mod[PowerMod[512, -1, 268369921]*1048560*PowerMod[2, 32, 268369921], 268369921]
#define BARRETT_REDUCE_V_C 1074397581 //const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) Q + 1;

#define QD 268238849
#define QINV_S64_D 4026728449  // q^(-1) mod 2^32
#define QINV_S32_D QINV_S64_D  // q^(-1) mod 2^32
#define ZETA_INV_FINAL_D 238198767 // Mod[PowerMod[512, -1, 268369921]*1048560*PowerMod[2, 32, 268369921], 268369921]
#define BARRETT_REDUCE_V_D 1074528829 //const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) Q + 1;

#define TWO_64_3_AB 45720068435305548
#define TWO_64_1_AB 9568774854278912
#define TWO_QB_QB_INV_A 38253045414225921
#define TWO_QA_QA_INV_B 43335945451206400

#define TWO_64_3_CD 43172655632792838
#define TWO_64_1_CD 24761414266650368
#define TWO_QD_QD_INV_C 16269986882028801
#define TWO_QC_QC_INV_D 8491427384621567

#define QA_INV_B 268328970
#define QB_INV_A 32760
#define QC_INV_D 268230663
#define QD_INV_C 8187

#define QAB_INV_CD 36635978864726773
#define QCD_INV_AB 35354023394372877

#define BARRETT_REDUCE_FACTOR_AB 118

#define NOISE_MAX_AB 498
#define NOISE_MAX_BYTES_AB 9

#define TWO_32_A 1048560
#define TWO_32_B 1179632

#define TWO_32_2_A 234877184
#define TWO_32_2_B 76090559

#define MESSAGE_BLOCK_SIZE 9984
#define C_MESSAGE_BLOCK_SIZE 10240

#define BLOCK_64 18446744073709551615U
#define BLOCK_48 281474976710655
#define BLOCK_28 268435455

#define BLOCK_112 ((int128_t)BLOCK_64|((int128_t)BLOCK_48<<64))

#define Q_ABCD ((int128_t)QA*(int128_t)QB*(int128_t)QC*(int128_t)QD)

#define MODP_112_P_LOW 6629966800723967
#define MODP_112_P_HIGH 523641125077
#define MODP_112_P (int128_t)MODP_112_P_LOW+((int128_t)MODP_112_P_HIGH<<64)

// 1/(Mod[2^99, q]/q*1.0)
#define TWO_99_RATIO 8177

#define Q_AB (int128_t)QA*QB
#define Q_AB_INV_S64 10706299326180761601U

#define Q_CD (int128_t)QC*QD
#define Q_CD_INV_S64 239491321889652737

#define PAD_SIZE 47
#define SAMPLE_BLOCK_SIZE 56
#define COEFFS_PER_BLOCK 4
#define BLOCK_SIZE NEWHOPE_N/COEFFS_PER_BLOCK*SAMPLE_BLOCK_SIZE