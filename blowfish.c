#include <stdlib.h>
#include <string.h>

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
	uint32_t i, t;
	for (i = 0; i < 16; i++) {
		*left  ^= pbox[i];
		*right ^= feistel_function(*left);
		
		SWAP(*left, *right, t);
	}

	SWAP(*left, *right, t);
	*right  ^= pbox[16];
	*left ^= pbox[17];
}

void
_decrypt(uint32_t *left, uint32_t *right)
{
	uint32_t i, t;
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
blowfish_init(uint8_t key[], int size)
{
	int keysize = size, i, j;
	uint32_t left = 0x00000000, right = 0x00000000;

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
}

uint8_t *
blowfish_encrypt(uint8_t data[], int padsize)
{
	uint8_t *encrypted = malloc(sizeof *encrypted * padsize);
	uint8_t byte;
	uint32_t i, j, index = 0;
	uint32_t left, right, datasize, factor;
	uint64_t chunk;
	
	datasize = padsize;

	for (i = 0; i < datasize; i += 8) {
		/* make 8 byte chunks */
		chunk = 0x0000000000000000;
		memmove(&chunk, data + i, sizeof(chunk)); 

		/* split into two 4 byte chunks */
		left = right = 0x00000000;
		left   = (uint32_t)(chunk >> 32);
		right  = (uint32_t)(chunk);

		_encrypt(&left, &right);

		/* merge encrypted halves into a single 8 byte chunk again */
		chunk = 0x0000000000000000;
		chunk |= left; chunk <<= 32;
		chunk |= right;
		
		/* append the chunk into the answer */
		memmove(encrypted + i, &chunk, sizeof(chunk));
	}
	return encrypted;
}

uint8_t *
blowfish_decrypt(uint8_t crypt_data[], int padsize)
{
	uint8_t *decrypted = malloc(sizeof *decrypted * padsize);
	uint8_t byte;
	uint32_t i, j, index = 0;
	uint32_t left, right, datasize, factor;
	uint64_t chunk;
	
	datasize = padsize;

	for (i = 0; i < datasize; i += 8) {
		chunk = 0x0000000000000000;
		memmove(&chunk, crypt_data + i, sizeof(chunk));

		left = right = 0x00000000;
		left   = (uint32_t)(chunk >> 32);
		right  = (uint32_t)(chunk);

		_decrypt(&left, &right);

		chunk = 0x0000000000000000;
		chunk |= left; chunk <<= 32;
		chunk |= right;
		
		memmove(decrypted + i, &chunk, sizeof(chunk));
	}
	return decrypted;
}

