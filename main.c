#include <stdio.h>
#include <string.h>
#include <math.h>

#include "blowfish.h"

/* MUST NOT BE ALTERED */
#define KEYSIZE   56
#define DATASIZE  1024

/* change these to change the ciphertext and the secret key */
#define PLAINTEXT "testing!"
#define KEY       "the key is you"

int main()
{
	int i, Osize, Psize, Pbyte;
	int KOsize, KPsize, KPbyte;
	uint8_t *encrypted,
		*decrypted,
	        key[KEYSIZE],
	        data[DATASIZE];

	/* no string NULL termination bugs now :) */
	memset(data, 0, DATASIZE);
	memset(key,  0, KEYSIZE);

	strncpy(data, PLAINTEXT, sizeof(data));
	strncpy(key, KEY, sizeof(key));

	Osize = strlen(data);            KOsize = strlen(key);
	Psize = ceil(Osize / 8.0) * 8;   KPsize = ceil(KOsize / 8.0) * 8;
	Pbyte = Psize - Osize;           KPbyte = KPsize - KOsize;
	
	/* padding bytes added to the data and key */
	memset(data + Osize, Pbyte, sizeof *data * Pbyte);
	memset(key + KOsize, KPbyte, sizeof *key * KPbyte);

	blowfish_init(key, KPsize);
	
	encrypted = blowfish_encrypt(data, Psize);
	
	printf("encrypted data: ");
	i = 0;
	while (i < Psize) {
		printf("%.2X%.2X%.2X%.2X ", encrypted[i], encrypted[i + 1],
				encrypted[i + 2], encrypted[i + 3]);
		printf("%.2X%.2X%.2X%.2X ", encrypted[i + 4], encrypted[i + 5],
				encrypted[i + 6], encrypted[i + 7]);
		i += 8;
	}
	printf("\n");

	decrypted = blowfish_decrypt(encrypted, Psize);

	/* unpadding */ 
	memset(data, 0, Psize);
	memmove(data, decrypted, Osize);
	
	printf("decrypted data: ");
	printf("%s\n", data);

	return 0;
}
