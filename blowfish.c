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

uint8_t *
blowfish_initialize(uint8_t data_array[], uint8_t key[])
{
	int datasize = strlen(data_array), keysize = strlen(key), i, j, factor;
	int enc_index = 0;
	uint64_t data_chunk = 0x00000000;
	uint32_t left = 0, right = 0;
	uint8_t *encrypted_data = malloc(sizeof *encrypted_data * datasize);

	/* subkey generation */
	for (i = 0; i < 18; i++) {
		pbox[i] ^= key[i % keysize] | key[(i + 1) % keysize] | 
		           key[(i + 2) % keysize] | key[(i + 3) % keysize];
	}

	for (i = 0; i < datasize; i += 8) {
		factor = 7;
		for (j = i; (j < (i + 7)) && (j < datasize); j++, factor--) {
			data_chunk |= data_array[j] << (8 * factor);
		}
		data_chunk |= data_array[i + 7];

		left  = (uint32_t)(data_chunk);
		right = (uint32_t)(data_chunk >> 32);

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

		/* combining the tow halves again */
		data_chunk = (uint64_t)right << 32 | left;

		factor = 7;
		for (i = 0; i < 8; i++, enc_index++) {
			encrypted_data[enc_index] = 
			                (uint8_t)(data_chunk >> (8 * factor));
		}
	}

	return encrypted_data;
}
