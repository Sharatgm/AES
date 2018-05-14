/*
	Moisés Montaño Copca A01272656
	Shara Teresa González Mena A01205254

	Compilar:
	gcc -g -O0 -Wall -msse2 -msse -march=native -maes aes_ni.cpp


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
	bool encrypt = FALSE;
	uint8_t *filerBuffer;
	uint8_t	*fileOutBuffer = NULL;
	//uint8_t encrypt = 0;

	printf("\n ------------ Proyecto Final Seguridad Informática -------------\n\tMoisés Montaño Copca\n\tShara Teresa González Mena\n\n");

	printf("Origin file: ");
	fgets(origin_file, 255, stdin);
	origin_file[strlen(origin_file) - 1] = 0;
	printf("Destination file: ");
	fgets(destination_file, 255, stdin);
	destination_file[strlen(destination_file) - 1] = 0;

	do {
		printf("Encrypt (e) or decrypt (d): ");
		fgets(enc, 9, stdin);
		enc[strlen(enc) - 1] = 0;
	} while (strcmp(enc, "e") && strcmp(enc, "d"));
	if (strcmp(enc, "e") == 0 ) encrypt = TRUE;
	else encrypt = FALSE;

	do {
		printf("Enter the key: (32 characters long, 0 - 9, a - f or A - F): ");
		fgets(key, 255, stdin);
		key[strlen(key) - 1] = 0;

		if (!validate_key(key)) {
			printf("Invalid key\n");
		}
	} while (!validate_key(key));

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
		//system("pause");
		fclose(fileOut);
		fclose(fileIn);
		return 0;
	}

	// Size of the file:
	// Seek to the end and then ask for the position and store it in size
	fseek(fileIn, 0L, SEEK_END);
	int size = ftell(fileIn);
	// always return to the first position of the file
	fseek(fileIn, 0L, SEEK_SET);
	rewind(fileIn);

	if (!encrypt && (size % 16) != 0) {
		printf("Invalid size %d\n", size);
		fclose(fileIn);
		system("pause");
		return 0;
	}

	if (encrypt) {
		// Leer el archivo en bloques de 16
		int extra = 16 - ((size + 1) % 16) + 1;
		int realSize = size + extra;
		filerBuffer = (uint8_t*)malloc((realSize) * sizeof(uint8_t));

		fread(filerBuffer, size, sizeof(uint8_t), fileIn);
		filerBuffer[size++] = 1;
		while (size < realSize) {
			filerBuffer[size++] = 0;
		}
		fileOutBuffer = (uint8_t*)malloc((realSize + 16) * sizeof(uint8_t));
		for (int i = 0; i < 16; i++) {
			fileOutBuffer[i] = (uint8_t)0;
		}
	}
	else
	{
		filerBuffer = (uint8_t*)malloc((size) * sizeof(uint8_t));
		fread(filerBuffer, size, sizeof(uint8_t), fileIn); // Read in the entire file

		fileOutBuffer = (uint8_t*)malloc((size) * sizeof(uint8_t));
	}

	fclose(fileIn);

	uint8_t enc_key[16];
	int out = 0;

	for (int i = 0; i < 32; i += 2) {
		enc_key[i / 2]  = hexToInt(key[i]) * 16;
		enc_key[i / 2] += hexToInt(key[i + 1]);
	}

	if (encrypt) {
		printf("\n----- Encrypting -----\n");
		StartCounter();
		encryptAesCBC(enc_key, filerBuffer, fileOutBuffer, size);
		printf("\nElapsed time in seconds: %lf ", GetCounter());
	}
	else {
		printf("\n----- Decrypting -----\n");
		StartCounter();
		decryptAesCBC(enc_key, filerBuffer, fileOutBuffer, size);
		printf("\nElapsed time in seconds: %lf ", GetCounter());
	}

	fileOut = NULL;
	int destinationFileSize;
	fopen_s(&fileOut, destination_file, "wb");
	if (fileOut) {
		if (encrypt) {
			destinationFileSize = size + 16;
		} else  {
			destinationFileSize = sizeWithoutPadding(fileOutBuffer, size - 16);
		}

		fwrite(fileOutBuffer, destinationFileSize, sizeof(uint8_t), fileOut);
		fclose(fileOut);
	}
	else {
		printf("Error writing file");
	}

	printf("\nSize of origin file: %i", size);
	printf("\nName of destination file: %s", destination_file);
		printf("\nSize of destination file: %i\n\n", size);

	system("pause");

	free(filerBuffer);
	return out;
}
#endif
