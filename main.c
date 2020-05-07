#include <stdio.h>
#include <string.h>

#include "blowfish.h"

#define KEYSIZE  56
#define DATASIZE 1024
#define DATAFILE "data.txt"
#define KEYFILE  "key.txt"
#define ENC_FILE "data.eNCrYpT"

int main(int argc, char const *argv[])
{
	int i;
	uint8_t data[DATASIZE], key[KEYSIZE], character, *encrypted;
	//uint8_t *decrypted;

	FILE *dataF = fopen(DATAFILE, "r+");
	FILE *keyF  = fopen(KEYFILE, "r");
	FILE *encF  = fopen(ENC_FILE, "w+");

	/* reading from the data file */
	i = 0;
	while (!feof(dataF)) {
		character = fgetc(dataF);

		printf("%c", character);
		data[i] = character;
		i += 1;
	}
	clearerr(dataF);
	printf("reading from the datafile done\n");

	/* reading from the key file */
	i = 0;
	while (!feof(keyF)) {
		character = fgetc(keyF);
		
		printf("%c", character);
		key[i] = character;
		i += 1;
	}
	clearerr(keyF);
	printf("reading from the keyfile done\n");

	encrypted = blowfish_initialize(data, key);
	fputs(encrypted, encF);
	printf("writing to the encrypted file done\n");
	clearerr(encF);

	fclose(dataF);
	fclose(keyF);
	fclose(encF);

	return 0;
}