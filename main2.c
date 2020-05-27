#include <stdio.h>
#include <string.h>

#include "blowfish.h"

#define KEYSIZE  56
#define DATASIZE 4096

int main()
{
	int i;
	uint8_t encrypted[DATASIZE],
	        key[KEYSIZE],
	        decrypted[DATASIZE],
	        original_data[DATASIZE];

	
	strncpy(key, "key", strlen("key"));
	strncpy(original_data, "abcd", strlen("abcd"));

	printf("original_data = ");
	i = 0;
	while (i < strlen(original_data)) {
		printf("%.2X ", original_data[i]);
		i += 1;
	}
	printf("\n");

	blowfish_init(key);
	
	strncpy(encrypted, blowfish_encrypt(original_data), DATASIZE);
	printf("encrypted data: ");

	i = 0;
	while (i < strlen(original_data)) {
		printf("%.2X ", encrypted[i]);
		i += 1;
	}
	printf("\n");

	strncpy(decrypted, blowfish_decrypt(encrypted), DATASIZE);
	printf("decrypted data: ");

	i = 0;
	while (i < strlen(original_data)) {
		printf("%.2X ", decrypted[i]);
		i += 1;
	}

	printf("\n");
	
	return 0;
}