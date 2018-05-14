#ifndef __AES_AUX_H__
#define __AES_AUX_H__


#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>
#include <time.h>

/* Windows.h -> archivo cabecera específico de Windows para la programación en lenguaje C/C++
que contiene las declaraciones de todas las funciones de la biblioteca Windows API

Windows.h incluye la libreria wincrypt.h que es la que será utilizada */

#include <Windows.h>

/* Libreria usada de https://gist.github.com/acapola/d5b940da024080dfaf5f */
/* QueryPerformanceCounter https://stackoverflow.com/questions/1739259/how-to-use-queryperformancecounter */


#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

#define DO_ENC_BLOCK(m,k) \
	do{\
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenclast_si128(m, k[10]);\
    }while(0)

#define DO_DEC_BLOCK(m,k) \
	do{\
        m = _mm_xor_si128       (m, k[10+0]); \
        m = _mm_aesdec_si128    (m, k[10+1]); \
        m = _mm_aesdec_si128    (m, k[10+2]); \
        m = _mm_aesdec_si128    (m, k[10+3]); \
        m = _mm_aesdec_si128    (m, k[10+4]); \
        m = _mm_aesdec_si128    (m, k[10+5]); \
        m = _mm_aesdec_si128    (m, k[10+6]); \
        m = _mm_aesdec_si128    (m, k[10+7]); \
        m = _mm_aesdec_si128    (m, k[10+8]); \
        m = _mm_aesdec_si128    (m, k[10+9]); \
        m = _mm_aesdeclast_si128(m, k[0]);\
    }while(0)

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

static void aes128_load_key(uint8_t *enc_key, __m128i *key_schedule) {
  key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
	key_schedule[1]  = AES_128_key_exp(key_schedule[0], 0x01);
	key_schedule[2]  = AES_128_key_exp(key_schedule[1], 0x02);
	key_schedule[3]  = AES_128_key_exp(key_schedule[2], 0x04);
	key_schedule[4]  = AES_128_key_exp(key_schedule[3], 0x08);
	key_schedule[5]  = AES_128_key_exp(key_schedule[4], 0x10);
	key_schedule[6]  = AES_128_key_exp(key_schedule[5], 0x20);
	key_schedule[7]  = AES_128_key_exp(key_schedule[6], 0x40);
	key_schedule[8]  = AES_128_key_exp(key_schedule[7], 0x80);
	key_schedule[9]  = AES_128_key_exp(key_schedule[8], 0x1B);
	key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
}

static void aes128_extended_key(uint8_t *enc_key, __m128i *key_schedule) {
	aes128_load_key(enc_key, key_schedule);

	for (int i = 1; i < 10; i++) {
		key_schedule[10 + i] = _mm_aesimc_si128(key_schedule[10 - i]);
	}
}

static void aes128_enc(__m128i *key_schedule, uint8_t *plainText, uint8_t *cipherText) {
	__m128i m = _mm_load_si128((__m128i *) plainText);

  DO_ENC_BLOCK(m, key_schedule);
	_mm_storeu_si128((__m128i *) cipherText, m);
}

static void aes128_dec(__m128i *key_schedule, uint8_t *cipherText, uint8_t *plainText) {
	__m128i m = _mm_loadu_si128((__m128i *) cipherText);

  DO_DEC_BLOCK(m,key_schedule);

	_mm_storeu_si128((__m128i *) plainText, m);
}


uint8_t IV[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

double PCFreq = 0.0;
__int64 CounterStart = 0;

void StartCounter()
{
    LARGE_INTEGER li;
    if(!QueryPerformanceFrequency(&li))
    printf("QueryPerformanceFrequency failed!\n");

    PCFreq = double(li.QuadPart);

    QueryPerformanceCounter(&li);
    CounterStart = li.QuadPart;
}
double GetCounter()
{
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return double(li.QuadPart-CounterStart)/PCFreq;
}



void encryptAesCBC(uint8_t enc_key[16], uint8_t *filerBuffer, uint8_t *fileOutBuffer, int size) {
	//encryptAesCBC(enc_key, filerBuffer, fileOutBuffer, sz);
	__m128i key_schedule[20];
	aes128_extended_key(enc_key, key_schedule);

	uint8_t *iv;
	for (int i = 0; i < 16; i++) {
		fileOutBuffer[i] = 0;
	}

  iv = fileOutBuffer;
	for (int i = 0; i < size; i += 16) {
		uint8_t tmp[16];
		for (int j = 0; j < 16; j++) {
			tmp[j] = fileOutBuffer[i + j] ^ filerBuffer[i + j];
		}
		aes128_enc(key_schedule, tmp, fileOutBuffer + 16 + i);
	}

}

void decryptAesCBC(uint8_t enc_key[16], uint8_t *filerBuffer, uint8_t *fileOutBuffer, int size) {
	__m128i key_schedule[20];
	aes128_extended_key(enc_key, key_schedule);

	aes128_extended_key(enc_key, key_schedule);
	uint8_t iv[16];
	for (int i = 0; i < 16; i++) iv[i] = fileOutBuffer[i];

	for (int i = 0; i < size; i += 16) {
		aes128_dec(key_schedule, filerBuffer + i + 16, fileOutBuffer + i);
		for (int j = 0; j < 16; j++) {
			fileOutBuffer[i + j] = fileOutBuffer[i + j] ^ filerBuffer[i + j];
		}
	}
}



int validate_key(char *pass) {
	int size = strlen(pass);
	if (size < 32) {
		printf("The key is shorter: %d\n", size);
		return false;
	} else if (size > 32) {
    printf("The key is larger: %d\n", size);
		return false;
  }

	for (int i = 0; i < 32; i++) {
    pass[i] = tolower(pass[i]);
    if (!((pass[i] >= 'a' && pass[i] <= 'f') || (pass[i] >= '0' && pass[i] <= '9'))) {
			printf("This character is not accepted: %c\n", pass[i]);
			return false;
		}
	}

	return true;
}

int hexToInt(char c) {
	//printf("%c ", c);
	if (c >= '0' && c <= '9') {
		return c - '0';
	}

	return c - 'a' + 10;
}

int sizeWithoutPadding(const uint8_t *s, int size) {
	for (int i = size - 1; i >= 0; i--) {
		if (s[i] == 1) {
			return i;
		}
	}

	return size;
}

#endif
