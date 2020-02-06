CC = /usr/bin/gcc
NISTFLAGS = -O3 -fomit-frame-pointer -march=native -fPIC -no-pie
CFLAGS = -no-pie -Wall -Wextra -g -O3 -fomit-frame-pointer -msse2avx -mavx2 -march=native

UTILS_DIR = ../utils


KECCAK = $(UTILS_DIR)/keccak4x/KeccakP-1600-times4-SIMD256.o

SHARED_HEADERS = $(UTILS_DIR)/aes_gcm.h
SHARED_SOURCES = $(UTILS_DIR)/aes_gcm.c $(UTILS_DIR)/fips202x4.c $(UTILS_DIR)/fips202.c

HEADERS_28 = 28/ntt_avx2.h 28/ntt_avx.h 28/ntt.h 28/consts.h 28/crypto_algorithms.h 
SOURCES_28 = 28/ntt_avx.c 28/ntt_268409857.s 28/ntt.c 28/consts.c 28/crypto_algorithms.c

HEADERS_60 = 60/ntt.h 60/consts.h 60/crypto_algorithms.h 
SOURCES_60 = 60/ntt.c 60/consts.c 60/crypto_algorithms.c

HEADERS_120 = 120/ntt.h 120/consts.h 120/crypto_algorithms.h 
SOURCES_120 = 120/ntt.c 120/consts.c 120/crypto_algorithms.c

HEADERS_128 = 128/ntt.h 128/consts.h 128/crypto_algorithms.h 
SOURCES_128 = 128/ntt.c 128/consts.c 128/crypto_algorithms.c

all:	UAE_LWE_28 UAE_LWE_60 UAE_LWE_120 UAE_LWE_128

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
