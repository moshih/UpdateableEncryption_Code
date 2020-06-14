CC = /usr/bin/gcc
NISTFLAGS = -O3 -fomit-frame-pointer -march=native -fPIC -no-pie
CFLAGS = -no-pie -Wall -Wextra -g -O3 -fomit-frame-pointer -msse2avx -mavx2 -march=native

UTILS_DIR = ../utils


KECCAK = $(UTILS_DIR)/keccak4x/KeccakP-1600-times4-SIMD256.o

SHARED_HEADERS = $(UTILS_DIR)/aes_gcm.h
SHARED_SOURCES = $(UTILS_DIR)/aes_gcm.c $(UTILS_DIR)/fips202x4.c $(UTILS_DIR)/fips202.c

HEADERS_28 = 28/ntt_avx2.h 28/ntt_avx.h 28/ntt.h 28/consts.h 28/crypto_algorithms.h 
SOURCES_28 = 28/ntt_avx.c 28/ntt_268409857.s 28/ntt.c 28/consts.c 28/crypto_algorithms.c

HEADERS_28_AB = 28_AB/ntt_avx2.h 28_AB/ntt_avx.h 28_AB/ntt_268369921.h 28_AB/ntt_268361729.h 28_AB/consts.h 28_AB/crypto_algorithms.h 
SOURCES_28_AB = 28_AB/ntt_avx.c 28_AB/ntt_268369921.s 28_AB/ntt_268361729.s 28_AB/ntt_268369921.c 28_AB/ntt_268361729.c 28_AB/consts.c 28_AB/crypto_algorithms.c 

HEADERS_28_ABC = 28_ABC/ntt_avx2.h 28_ABC/ntt_avx.h 28_ABC/ntt_268369921.h 28_ABC/ntt_268361729.h 28_ABC/ntt_268271617.h 28_ABC/consts.h 28_ABC/crypto_algorithms.h 
SOURCES_28_ABC = 28_ABC/ntt_avx.c 28_ABC/ntt_268369921.s 28_ABC/ntt_268361729.s 28_ABC/ntt_268271617.s 28_ABC/ntt_268369921.c 28_ABC/ntt_268361729.c 28_ABC/ntt_268271617.c 28_ABC/consts.c 28_ABC/crypto_algorithms.c  

HEADERS_28_ABCD = 28_ABCD/ntt_avx2.h 28_ABCD/ntt_avx.h 28_ABCD/ntt_268369921.h 28_ABCD/ntt_268361729.h 28_ABCD/ntt_268271617.h 28_ABCD/ntt_268238849.h 28_ABCD/consts.h 28_ABCD/crypto_algorithms.h 
SOURCES_28_ABCD = 28_ABCD/ntt_avx.c 28_ABCD/ntt_268369921.s 28_ABCD/ntt_268361729.s 28_ABCD/ntt_268271617.s 28_ABCD/ntt_268238849.s 28_ABCD/ntt_268369921.c 28_ABCD/ntt_268361729.c 28_ABCD/ntt_268271617.c 28_ABCD/ntt_268238849.c 28_ABCD/consts.c 28_ABCD/crypto_algorithms.c  

HEADERS_60 = 60/ntt.h 60/consts.h 60/crypto_algorithms.h 
SOURCES_60 = 60/ntt.c 60/consts.c 60/crypto_algorithms.c

HEADERS_60_AB = 60_AB/ntt_A.h 60_AB/ntt_B.h 60_AB/consts.h 60_AB/crypto_algorithms.h 
SOURCES_60_AB = 60_AB/ntt_A.c 60_AB/ntt_B.c 60_AB/consts.c 60_AB/crypto_algorithms.c

HEADERS_120 = 120/ntt.h 120/consts.h 120/crypto_algorithms.h 
SOURCES_120 = 120/ntt.c 120/consts.c 120/crypto_algorithms.c

HEADERS_128 = 128/ntt.h 128/consts.h 128/crypto_algorithms.h 
SOURCES_128 = 128/ntt.c 128/consts.c 128/crypto_algorithms.c

all:	TEST_60_AB TEST_ABCD TEST_ABC TEST_AB  UAE_LWE_28 UAE_LWE_60 UAE_LWE_120 UAE_LWE_128

TEST_60_AB: $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_60_AB) $(HEADERS_60_AB) $(KECCAK)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_60_AB) $(HEADERS_60_AB) $(KECCAK) -msse2avx -mavx2 60_AB/UAE_60_AB.c -o 60_AB/uae_lwe_28 -lcrypto

TEST_ABCD: $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_28_ABCD) $(HEADERS_28_ABCD) $(KECCAK)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_28_ABCD) $(HEADERS_28_ABCD) $(KECCAK) -msse2avx -mavx2 28_ABCD/UAE_28_ABCD.c -o 28_ABCD/uae_lwe_28 -lcrypto

TEST_ABC: $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_28_ABC) $(HEADERS_28_ABC) $(KECCAK)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_28_ABC) $(HEADERS_28_ABC) $(KECCAK) -msse2avx -mavx2 28_ABC/UAE_28_ABC.c -o 28_ABC/uae_lwe_28 -lcrypto

TEST_AB: $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_28_AB) $(HEADERS_28_AB) $(KECCAK)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_28_AB) $(HEADERS_28_AB) $(KECCAK) -msse2avx -mavx2 28_AB/UAE_28_AB.c -o 28_AB/uae_lwe_28 -lcrypto

UAE_LWE_128: $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_128) $(HEADERS_128) $(KECCAK)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) -DMODULO=128 $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_128) $(HEADERS_128) $(KECCAK) -msse2avx -mavx2 128/UAE_128.c -o 128/uae_lwe_128 -lcrypto

UAE_LWE_120: $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_120) $(HEADERS_120) $(KECCAK)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) -DMODULO=120 $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_120) $(HEADERS_120) $(KECCAK) -msse2avx -mavx2 120/UAE_120.c -o 120/uae_lwe_120 -lcrypto

UAE_LWE_60: $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_60) $(HEADERS_60) $(KECCAK)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) -DMODULO=602048 $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_60) $(HEADERS_60) $(KECCAK) -msse2avx -mavx2 60/UAE_60.c -o 60/uae_lwe_60 -lcrypto

UAE_LWE_28: $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_28) $(HEADERS_28) $(KECCAK)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) -DMODULO=268409857 $(SHARED_HEADERS) $(SHARED_SOURCES) $(SOURCES_28) $(HEADERS_28) $(KECCAK) -msse2avx -mavx2 28/UAE_28.c -o 28/uae_lwe_28 -lcrypto

keccak4x/KeccakP-1600-times4-SIMD256.o: keccak4x/KeccakP-1600-times4-SIMD256.c \
																				keccak4x/align.h \
																				keccak4x/brg_endian.h \
																				keccak4x/KeccakP-1600-times4-SIMD256.c \
																				keccak4x/KeccakP-1600-times4-SnP.h \
																				keccak4x/KeccakP-1600-unrolling.macros \
																				keccak4x/SIMD256-config.h
	$(CC) $(CFLAGS) -c $(UTILS_DIR)/keccak4x/KeccakP-1600-times4-SIMD256.c -o $@

.PHONY: clean

clean:
	-rm 128/uae_lwe_128
	-rm 120/uae_lwe_120
	-rm 60/uae_lwe_60
	-rm 28/uae_lwe_28
	-rm 28_AB/uae_lwe_28
	-rm 28_ABC/uae_lwe_28
	-rm 28_ABCD/uae_lwe_28
	-rm 60_AB/uae_lwe_28
