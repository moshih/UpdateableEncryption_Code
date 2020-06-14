#include <stdio.h>
#include <stdint.h>

#include "ntt_avx2_268369921.h"

void inv_ntt_avx_268369921(int32_t *r, const int32_t *zetas_inv_asm);
void ntt_avx_268369921(int32_t *r, const int32_t *zetas_asm);