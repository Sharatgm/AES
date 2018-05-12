/* To compile it:
	gcc -g -O0 -Wall -msse2 -msse -march=native -maes aes.cpp


*/

#ifndef __AES_H__
#define __AES_H__

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
#include "aes.h"

int main(int argc, char **argv) {
	char origin_file[256];
	char destination_file[256];
	char key[256];
	char enc[256];
	uint8_t *filerBuffer;
	uint8_t	*fileOutBuffer = NULL;
	uint8_t encrypting = 0;

	if (argc == 4) {
		strcpy_s(enc, argv[1]);
		strcpy_s(origin_file, argv[2]);
		strcpy_s(destination_file, argv[3]);

		if (strcmp(enc, "-e") && strcmp(enc, "-d")) {
			printf("Parametros invalidos\n aes.exe (-e|-d) origin_file destination_file\n");
			return 0;
		}
		encrypting = (strcmp(enc, "-e") == 0) ? 1 : 0;
	}
	else {
		printf("Origin file: ");
		fgets(origin_file, 255, stdin);
		origin_file[strlen(origin_file) - 1] = 0;
		printf("Destination file: ");
		fgets(destination_file, 255, stdin);
		destination_file[strlen(destination_file) - 1] = 0;

		enc[0] = 0;
		while (strcmp(enc, "e") && strcmp(enc, "d")) {
			printf("Encrypt (e) or decrypt (d) ?: ");
			fgets(enc, 255, stdin);
			//printf("\nENC: |%s|\n", enc);
			enc[strlen(enc) - 1] = 0;

		}
		encrypting = (strcmp(enc, "e") == 0) ? 1 : 0;
	}

	key[0] = 0;
	while (!validate_key(key)) {
		printf("Enter the key: (32 characters long, 0 - 9, a - f or A - F): ");
		fgets(key, 255, stdin);
		key[strlen(key) - 1] = 0;

		if (!validate_key(key)) {
			printf("Invalid key\n");
		}
	}

	FILE *fileIn;
	fopen_s(&fileIn, origin_file, "rb");
	if (!fileIn) {
		printf("The origin file %s does not exist\n", origin_file);
		system("pause");
		return 0;
	}

	FILE *fileOut;
	fopen_s(&fileOut, destination_file, "r");
	if (fileOut) {
		printf("Destination file %s already exists\n", destination_file);
		system("pause");
		fclose(fileOut);
		fclose(fileIn);
		return 0;
	}

	fseek(fileIn, 0L, SEEK_END);
	int sz = ftell(fileIn);
	rewind(fileIn);

	if (!encrypting && (sz % 16) != 0) {
		printf("Invalid size %d\n", sz);
		fclose(fileIn);
		system("pause");
		return 0;
	}

	if (encrypting) {
		int paddingSize = addPaddingSize(sz) ;
		int realSize = sz + paddingSize;
		filerBuffer = (uint8_t*)malloc((realSize) * sizeof(uint8_t));

		fread(filerBuffer, sz, sizeof(uint8_t), fileIn); // Read in the entire file
		filerBuffer[sz++] = 1;
		while (sz < realSize) {
			filerBuffer[sz++] = 0;
		}

		int x = realSize + 16;

		fileOutBuffer = (uint8_t*)malloc((realSize + 16) * sizeof(uint8_t));
		for (int i = 0; i < 16; i++) {
			fileOutBuffer[i] = (uint8_t)0;
		}
	}
	else
	{
		filerBuffer = (uint8_t*)malloc((sz) * sizeof(uint8_t));
		fread(filerBuffer, sz, sizeof(uint8_t), fileIn); // Read in the entire file

		fileOutBuffer = (uint8_t*)malloc((sz) * sizeof(uint8_t));
	}

	fclose(fileIn);

	// Real encryption
	uint8_t enc_key[16];
	int out = 0;

	for (int i = 0; i < 32; i += 2) {
		enc_key[i / 2]  = hexToInt(key[i]) * 16;
		enc_key[i / 2] += hexToInt(key[i + 1]);
	}

	pretty_print(enc_key, 16);

	if (encrypting) {
		encryptAesCBC(enc_key, filerBuffer, fileOutBuffer, sz);
	}
	else {
		decryptAesCBC(enc_key, filerBuffer, fileOutBuffer, sz);
	}

	fileOut = NULL;
	fopen_s(&fileOut, destination_file, "wb");
	if (fileOut) {

		int fileOutSize = (encrypting) ? sz + 16 : sizeWithoutPadding(fileOutBuffer, sz - 16);
		printf("Writting file %d\n", fileOutSize);

		fwrite(fileOutBuffer, fileOutSize, sizeof(uint8_t), fileOut);
		fclose(fileOut);
	}
	else {
		printf("Error writing file");
	}


	printf("Fin\n");
	system("pause");

	free(filerBuffer);
	//free(fileOutBuffer);

	return out;
}
#endif
