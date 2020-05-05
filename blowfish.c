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
blowfish_encrypt(uint32_t *left, uint32_t *right)
{
	int i;
	for (i = 0; i < 16; i += 2) {
		*left  ^= pbox[i];
		*right ^= feistel_function(*left);
		*right ^= pbox[i + 1];
		*left  ^= feistel_function(*right);
	}

	*left  ^= pbox[16];
	*right ^= pbox[17];
	SWAP(*left, *right);
}

void
blowfish_decrypt(uint32_t *left, uint32_t *right)
{
	int i;
	for (i = 16; i > 0; i -= 2) {
		*left  ^= pbox[i + 1];
		*right ^= feistel_function(*left);
		*right ^= pbox[i];
		*left  ^= feistel_function(*right);
	}

	*left  ^=  pbox[1];
	*right ^= pbox[0];
	SWAP(*left, *right);
}

void
blowfish_initialize(uint8_t *key, uint8_t keysize)
{
	int keylen = strlen(key), i, j;
	uint32_t left = 0, right = 0;

	/* subkey generation */
	for (i = 0; i < 18; i++) {
		pbox[i] ^= key[i % keylen] | key[(i + 1) % keylen] | 
		           key[(i + 2) % keylen] | key[(i + 3) % keylen];
	}

	/* TODO:
	 * 1. break the data into two 32 bit chunks
	 * 2. encrypt these two chunks
	 * 3. append to the answer as a single 64 bit chunk again
	 * 4. process next 64 bit block, repeat 1.
	 */

	/* encrypt left and right using pbox */
	for (i = 0; i < 18; i += 2) {
		blowfish_encrypt(&left, &right);
		pbox[i]     = left;
		pbox[i + 1] = right;
	}

	/* further encrypt left and right using sbox */
	for (i = 0; i < 5; i++) {
		for (j = 0; j < 256; j += 2) {
			blowfish_encrypt(&left, &right);
			sbox[i][j]     = left;
			sbox[i][j + 1] = right;
		}
	}
}
