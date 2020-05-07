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
blowfish_encrypt(uint32_t *left, uint32_t *right)
{
	int i;
	for (i = 0; i <= 16; i += 2) {
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
	for (i = 16; i > 1; i -= 2) {
		*left  ^= pbox[i + 1];
		*right ^= feistel_function(*left);
		*right ^= pbox[i];
		*left  ^= feistel_function(*right);
	}

	*left  ^=  pbox[1];
	*right ^= pbox[0];
	SWAP(*left, *right);
}

uint8_t *
blowfish_initialize(uint8_t data_array[], uint8_t key[], uint8_t op_mode)
{
	int datasize = strlen(data_array), keysize = strlen(key), i, j, k, 
	    factor;
	int index = 0;
	uint64_t data_chunk = 0x0000000000000000;
	uint32_t left = 0, right = 0;
	uint8_t *encrypted = malloc(sizeof *encrypted * datasize);

	/* subkey generation */
	for (i = 0; i < 18; i++) {
		pbox[i] ^= ((uint32_t)key[(i + 0) % keysize] << 24) | 
		           ((uint32_t)key[(i + 1) % keysize] << 16) | 
		           ((uint32_t)key[(i + 2) % keysize] <<  8) | 
		           ((uint32_t)key[(i + 3) % keysize]);
	}

	for (k = 0; k < datasize; k += 8) {

		/* chunkify */
		factor = 7;
		for (j = k; (j < (k + 7)) && (factor > 0); j++, factor--) {
			data_chunk |= data_array[j] << (8 * factor);
		}
		data_chunk |= data_array[k + 7];

		left   = (uint32_t)(data_chunk >> 32);
		right  = (uint32_t)(data_chunk);

		/* main encryption engine */
		for (i = 0; i <= 16; i += 2) {
			if (op_mode == 1)
				blowfish_encrypt(&left, &right);
			else
				blowfish_decrypt(&left, &right);
			
			pbox[i]     = left;
			pbox[i + 1] = right;
		}

		for (i = 0; i <= 3; i++) {
			for (j = 0; j <= 254; j += 2) {
				if (op_mode == 1)
					blowfish_encrypt(&left, &right);
				else
					blowfish_decrypt(&left, &right);

				sbox[i][j]     = left;
				sbox[i][j + 1] = right;
			}
		}
		
		/* combining the tow halves again */
		data_chunk = ((uint64_t)left << 32) | right;

		/* converting 64-bit chunk into string format again */
		factor = 7, index = k;
		while (index < datasize - 1 && factor >= 1) {
			encrypted[index] = (uint8_t)(data_chunk >> (8*factor));
			
			factor -= 1;
			index  += 1;
		}
		encrypted[index] = (uint8_t)data_chunk;

		index += 1;
	}

	return encrypted;
}

