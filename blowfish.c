#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "blowfish.h"
#include "constants.h"

uint32_t 
feistel_function(uint32_t arg)
{
	uint32_t var = sbox[0][arg >> 24] + sbox[1][(uint8_t)(arg >> 16)];
	return (var ^ sbox[2][(uint8_t)(arg >> 8)]) + sbox[3][(uint8_t)(arg)];
}

void 
_encrypt(uint32_t *left, uint32_t *right)
{
	int i, t;
	for (i = 0; i < 16; i++) {
		/* check the value of each iteration and then compare the values
		 * with manual caluclations */
		*left  ^= pbox[i];
		*right ^= feistel_function(*left);
		
		SWAP(*left, *right, t);
	}

	SWAP(*left, *right, t); i += 1;
	
	*right  ^= pbox[16];
	*left ^= pbox[17];
}

void
_decrypt(uint32_t *left, uint32_t *right)
{
	int i, t;
	for (i = 17; i > 1; i--) {
		*left  ^= pbox[i];
		*right ^= feistel_function(*left);

		SWAP(*left, *right, t);
	}

	SWAP(*left, *right, t);
	*right ^=  pbox[1];
	*left  ^= pbox[0];
}

void
blowfish_init(uint8_t key[])
{
	int keysize = strlen(key), i, j, k, factor;
	int index = 0;
	uint32_t left = 0, right = 0;

	/* subkey generation */
	for (i = 0; i < 18; i++) {
		pbox[i] ^= ((uint32_t)key[(i + 0) % keysize] << 24) | 
		           ((uint32_t)key[(i + 1) % keysize] << 16) | 
		           ((uint32_t)key[(i + 2) % keysize] <<  8) | 
		           ((uint32_t)key[(i + 3) % keysize]);
	}

	/* encrypt the zeroes, modifying the p-array and s-boxes accordingly */
	for (i = 0; i <= 17; i += 2) {
		_encrypt(&left, &right);
		
		pbox[i]     = left;
		pbox[i + 1] = right;
	}

	for (i = 0; i <= 3; i++) {
		for (j = 0; j <= 254; j += 2) {
			_encrypt(&left, &right);
			
			sbox[i][j]     = left;
			sbox[i][j + 1] = right;
		}
	}
	return;
}

uint8_t *
blowfish_encrypt(uint8_t data[])
{
	int i, j, index = 0;
	uint32_t left = 0, right = 0, datasize = strlen(data), factor;
	uint64_t chunk = 0;
	uint8_t *encrypted = malloc(sizeof *encrypted * datasize);

	/* CHUNK-IFY! */
	for (i = 0; i < datasize; i += 8) {
		chunk = 0x00000000;
		factor = 7;
		for (j = i; (j <= (i + 6)) && (j < datasize); j++, factor--) {
			chunk |= (uint64_t)(data[j] << (8 * factor));
		}
		if (factor == 0) {
			chunk |= data[i + 7];
		}

		printf("chunk before encryption: %X\n", chunk);
		left   = (chunk >> 32);
		right  = (uint32_t)(chunk);

		printf("left right before enc = %X, %X\n", left, right);
		/* main encryption engine */
		_encrypt(&left, &right);
		printf("left right after enc = %X, %X\n", left, right);

		/* merge the two halves again, into a single 64 bit chunk */
		chunk = 0;
		chunk |= (uint64_t)left << 32;
		chunk |= right;
		// chunk = ((uint64_t)(left) << 32) | right;
		printf("chunk after encryption: %X\n", chunk);
				
		/* copy this chunk into the final answer */	
		encrypted[index + 0] = (uint8_t)(chunk >> 56);
		printf("chunk >> %d = %X\n", 8*7, (chunk >> 56) & 0xff);
		encrypted[index + 1] = (uint8_t)(chunk >> 48);
		printf("chunk >> %d = %X\n", 8*6, (chunk >> 48) & 0xff);
		encrypted[index + 2] = (uint8_t)(chunk >> 40);
		printf("chunk >> %d = %X\n", 8*5, (chunk >> 40) & 0xff);
		encrypted[index + 3] = (uint8_t)(chunk >> 32);
		printf("chunk >> %d = %X\n", 8*4, (chunk >> 32) & 0xff);
		encrypted[index + 4] = (uint8_t)(chunk >> 24);
		printf("chunk >> %d = %X\n", 8*3, (chunk >> 24) & 0xff);
		encrypted[index + 4] = (uint8_t)(chunk >> 16);
		printf("chunk >> %d = %X\n", 8*2, (chunk >> 16) & 0xff);
		encrypted[index + 5] = (uint8_t)(chunk >> 8);
		printf("chunk >> %d = %X\n", 8*1, (chunk >> 8) & 0xff);
		encrypted[index + 7] = (uint8_t)(chunk);
		printf("chunk >> %d = %X\n", 8*0, (chunk) & 0xff);

		index += 8;
	}
	return encrypted;
}

uint8_t *
blowfish_decrypt(uint8_t data[])
{
	int i, j, index = 0;
	uint32_t left = 0, right = 0, datasize = strlen(data), factor;
	uint64_t chunk = 0;
	uint8_t *decrypted = malloc(sizeof *decrypted * datasize);

	/* CHUNK-IFY! */
	for (i = 0; i < datasize; i += 8) {
		chunk = 0x00000000;
		factor = 7;
		for (j = i; (j <= (i + 6)) && (j < datasize); j++, factor--) {
			chunk |= data[j] << (8 * factor);
		}
		if (j < datasize) {
			chunk |= data[i + 7];
		}


		// left   = (uint32_t)(chunk >> 32);
		left   = (chunk >> 32) & 0xffffffff;
		right  = (chunk);
		// right  = (uint32_t)(chunk);

		printf("chunk before decryption = %X\n", chunk);
		printf("left right before decryption = %X, %X\n", left, right);
		_decrypt(&left, &right);

		chunk = (((uint64_t)left << 32) & 0xffffffff) | right;
		printf("left right after decryption = %X, %X\n", left, right);
		printf("chunk before decryption = %X\n", chunk);
				
		/* copy this chunk into the final answer */
		decrypted[index + 0] = (chunk >> 56) & 0xff;
		printf("chunk >> %d = %X\n", 8*7, (chunk >> 56) & 0xff);
		decrypted[index + 1] = (chunk >> 48) & 0xff;
		printf("chunk >> %d = %X\n", 8*6, (chunk >> 48) & 0xff);
		decrypted[index + 2] = (chunk >> 40) & 0xff;
		printf("chunk >> %d = %X\n", 8*5, (chunk >> 40) & 0xff);
		decrypted[index + 3] = (chunk >> 32) & 0xff;
		printf("chunk >> %d = %X\n", 8*4, (chunk >> 32) & 0xff) ;
		decrypted[index + 4] = (chunk >> 24) & 0xff;
		printf("chunk >> %d = %X\n", 8*3, (chunk >> 24) & 0xff);
		decrypted[index + 4] = (chunk >> 16) & 0xff;
		printf("chunk >> %d = %X\n", 8*2, (chunk >> 16) & 0xff);
		decrypted[index + 5] = (chunk >> 8) & 0xff;
		printf("chunk >> %d = %X\n", 8*1, (chunk >> 8) & 0xff);
		decrypted[index + 7] = (chunk) & 0xff; 
		printf("chunk >> %d = %X\n", 8*0, (chunk) & 0xff);
		
		index += 8;
	}
	return decrypted;
}
