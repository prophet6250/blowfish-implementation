#include <stdio.h>
#include <string.h>
#include <math.h>

#include "blowfish.h"

#define KEYSIZE  56
#define DATASIZE 8192

int main()
{
	int i, Osize, Psize, Pbyte;
	int KOsize, KPsize, KPbyte;
	uint8_t *encrypted,
		*decrypted,
	        key[KEYSIZE],
	        data[DATASIZE];

	/* to avoid the NULL termination bugs */
	memset(data, 0, DATASIZE);
	memset(key,  0, KEYSIZE);

	/* see the manpage of snprintf for more details */
	strncpy(data, "Avantika, I did it!", sizeof("Avantika, I did it!"));
	strncpy(key, "key is you", sizeof("key is you"));

	/* data and key padding variables */
	/* check for NULL termination errors in the below code, if necessary */
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
	
	printf("decryption data: ");
	printf("%s\n", data);

	return 0;
}
