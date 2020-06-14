#include <stdint.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#define addition_buf 128

#define IV_LEN 16
#define TAG_LEN 16
#define AE_KEY_LEN 16

#define PAD_SIZE 39
#define C_PAD_SIZE 10

#define POLY_SIZE 4096
#define NEWHOPE_SYMBYTES 32   /* size of shared key, seeds/coins, and hashes */
#define SHAKE128_RATE 168
#define P_16_BLOCK 65535

#define NEWHOPE_N 2048
#define SAMPLE_BLOCK_SIZE 14
#define BLOCK_SIZE NEWHOPE_N/2*SAMPLE_BLOCK_SIZE

typedef struct{ 
  int32_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_28;

typedef struct{ 
  int64_t __attribute__((aligned(32))) coeffs[NEWHOPE_N];
} poly_56;

#define QA 268369921
#define QINV_S64_A 4026597377  // q^(-1) mod 2^32
#define QINV_S32_A QINV_S64_A  // q^(-1) mod 2^32

#define BARRETT_REDUCE_FACTOR  58 // floor(Log2[q])-1+32
#define ZETA_INV_FINAL_A 201506813 // Mod[PowerMod[512, -1, 268369921]*1048560*PowerMod[2, 32, 268369921], 268369921]

#define NOISE_MAX 352
#define NOISE_MAX_FACTOR 11
#define NOISE_MULT_MAX (NOISE_MAX+1)*NOISE_MAX_FACTOR

#define BARRETT_REDUCE_V_A 1074004029 //const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) Q + 1;

int pad_array(int8_t *buf, int size);
int unpad_array(int8_t *buf, int size);

#define QB 268361729
#define QINV_S64_B 872488961  // q^(-1) mod 2^32
#define QINV_S32_B QINV_S64_B  // q^(-1) mod 2^32
#define ZETA_INV_FINAL_B 218380284 // Mod[PowerMod[512, -1, 268369921]*1048560*PowerMod[2, 32, 268369921], 268369921]
#define BARRETT_REDUCE_V_B 1074036814 //const int64_t v = ((int64_t) 1U << BARRETT_REDUCE_FACTOR) / (int64_t) Q + 1;

// AB
#define Q_AB 72020216011153409
#define QINV_S64 10706299326180761601U

#define TWO_64 9568774854278912

#define QA_INV_B 268328970
#define QB_INV_A 32760

// QA/QB times their inverse times TWO_64
#define QA_QA_INV_B 65113173718608068
#define QB_QB_INV_A 49989512058411774

#define BARRETT_REDUCE_FACTOR_AB 118

#define NOISE_MAX_AB 498
#define NOISE_MAX_BYTES_AB 9

#define TWO_32_2_A 234877184
#define TWO_32_2_B 76090559

#define MESSAGE_BLOCK_SIZE 9984
#define C_MESSAGE_BLOCK_SIZE 10240