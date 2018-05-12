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


#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

char easytolower(char in) {
  if(in <= 'Z' && in >= 'A')
    return in - ('Z' - 'z');
  return in;
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

char intToHex(uint8_t n) {
	//printf("(%d)", n);
	if (n <= 9) {
		return n + '0';
	}
	return (n - 10) + 'a';
}

int addPaddingSize(int size) {
	return 16 - ((size + 1) % 16) + 1;
}

int sizeWithoutPadding(const uint8_t *s, int size) {
	for (int i = size - 1; i >= 0; i--) {
		if (s[i] == 1) {
			return i;
		}
	}

	return size;
}

void pretty_print(uint8_t* a, int size) {
	for (int i = 0; i < size; i++) {
		//printf("%d ", a[i]);
		printf("%c%c", intToHex(a[i] / 16), intToHex(a[i] % 16));
	}
	printf("\n");
}

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

static void generateExtendedKeyFirstPart(uint8_t *enc_key, __m128i *extendedKey) {
	extendedKey[0] = _mm_loadu_si128((const __m128i*) enc_key);
	extendedKey[1] = AES_128_key_exp(extendedKey[0], 0x01);
	extendedKey[2] = AES_128_key_exp(extendedKey[1], 0x02);
	extendedKey[3] = AES_128_key_exp(extendedKey[2], 0x04);
	extendedKey[4] = AES_128_key_exp(extendedKey[3], 0x08);
	extendedKey[5] = AES_128_key_exp(extendedKey[4], 0x10);
	extendedKey[6] = AES_128_key_exp(extendedKey[5], 0x20);
	extendedKey[7] = AES_128_key_exp(extendedKey[6], 0x40);
	extendedKey[8] = AES_128_key_exp(extendedKey[7], 0x80);
	extendedKey[9] = AES_128_key_exp(extendedKey[8], 0x1B);
	extendedKey[10] = AES_128_key_exp(extendedKey[9], 0x36);
}

static void generateExtendedKey(uint8_t *enc_key, __m128i *extendedKey) {
	generateExtendedKeyFirstPart(enc_key, extendedKey);

	for (int i = 1; i < 10; i++) {
		extendedKey[10 + i] = _mm_aesimc_si128(extendedKey[10 - i]);
	}
}

static void aes128_enc(__m128i *key_schedule, uint8_t *plainText, uint8_t *cipherText) {
	__m128i m = _mm_load_si128((__m128i *) plainText);

	m = _mm_xor_si128(m, key_schedule[0]);
	for (int i = 1; i < 10; i++) {
		m = _mm_aesenc_si128(m, key_schedule[i]);
	}
	m = _mm_aesenclast_si128(m, key_schedule[10]);

	_mm_storeu_si128((__m128i *) cipherText, m);
}

static void aes128_dec(__m128i *key_schedule, uint8_t *cipherText, uint8_t *plainText) {
	__m128i m = _mm_loadu_si128((__m128i *) cipherText);

	m = _mm_xor_si128(m, key_schedule[10]);
	for (int i = 11; i < 20; i++) {
		m = _mm_aesdec_si128(m, key_schedule[i]);
	}
	m = _mm_aesdeclast_si128(m, key_schedule[0]);

	_mm_storeu_si128((__m128i *) plainText, m);
}


uint8_t IV[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

void encryptAesCBC(uint8_t enc_key[16], uint8_t *filerBuffer, uint8_t *fileOutBuffer, int size) {
	//encryptAesCBC(enc_key, filerBuffer, fileOutBuffer, sz);
	__m128i key_schedule[20];

	LARGE_INTEGER frequency;        // ticks per second
	LARGE_INTEGER t1, t2;           // ticks
	double elapsedTime;

	// get ticks per second
	QueryPerformanceFrequency(&frequency);

	// start timer
	QueryPerformanceCounter(&t1);

	generateExtendedKey(enc_key, key_schedule);

	uint8_t *iv;
	for (int i = 0; i < 16; i++) {
		fileOutBuffer[i] = 0;
	}

	//memset(fileOutBuffer, 0, 16);
	iv = fileOutBuffer;
	for (int i = 0; i < size; i += 16) {
		uint8_t tmp[16];
		for (int j = 0; j < 16; j++) {
			tmp[j] = fileOutBuffer[i + j] ^ filerBuffer[i + j];
		}
		aes128_enc(key_schedule, tmp, fileOutBuffer + 16 + i);
	}


	QueryPerformanceCounter(&t2);

	// compute and print the elapsed time in millisec
	elapsedTime = (t2.QuadPart - t1.QuadPart) * 1.0 / frequency.QuadPart;
	printf("Tiempo de cifrado %fs with %d bytes", elapsedTime, size);

}

void decryptAesCBC(uint8_t enc_key[16], uint8_t *filerBuffer, uint8_t *fileOutBuffer, int size) {
	__m128i key_schedule[20];

	LARGE_INTEGER frequency;        // ticks per second
	LARGE_INTEGER t1, t2;           // ticks
	double elapsedTime;

	// get ticks per second
	QueryPerformanceFrequency(&frequency);

	// start timer
	QueryPerformanceCounter(&t1);

	generateExtendedKey(enc_key, key_schedule);

	generateExtendedKey(enc_key, key_schedule);
	uint8_t iv[16];
	for (int i = 0; i < 16; i++) iv[i] = fileOutBuffer[i];

	for (int i = 0; i < size; i += 16) {
		aes128_dec(key_schedule, filerBuffer + i + 16, fileOutBuffer + i);
		for (int j = 0; j < 16; j++) {
			fileOutBuffer[i + j] = fileOutBuffer[i + j] ^ filerBuffer[i + j];
		}
	}

	QueryPerformanceCounter(&t2);

	// compute and print the elapsed time in millisec
	elapsedTime = (t2.QuadPart - t1.QuadPart) * 1.0 / frequency.QuadPart;
	printf("Time %.10fs with %d bytes", elapsedTime, size);

}


#endif
