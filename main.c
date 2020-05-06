#include <stdio.h>
#include <string.h>

#include "blowfish.h"

#define KEYSIZE  56
#define DATASIZE 1024

int main(int argc, char const *argv[])
{
	int i;
	uint8_t data[DATASIZE] = "abcd", key[KEYSIZE] = "key", *encrypted;
	
	printf("enter the data (max length 1024 characters)\n");
	// fgets(data, DATASIZE, stdin);

	printf("enter key (max length = 56 characters)\n");
	// fgets(key, KEYSIZE, stdin);

	encrypted = blowfish_initialize(data, key);

	printf("encrypted data is:\n");
	for (i = 0; i < strlen(data); i++) {
		printf("%x ", encrypted[i]);
	}

	printf("\n");
	return 0;
}