#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "blowfish.h"
#include "constants.h"

uint32_t 
feistel_function(uint32_t arg)
{
	uint32_t var = sbox[0][arg >> 24] + sbox[1][(uint8_t)(x >> 16)];
	return (var ^ sbox[2][(uint8_t)(arg >> 8)]) + sbox[3][(uint8_t)(x)];
}

void 
blowfish_encrypt(uint32_t *left, uint32_t *right)
{
	int i;
	for (i = 0; i < 16; i += 2) {
		left  ^= pbox[i];
		right ^= feistel_function(left);
		right ^= pbox[i + 1];
		left  ^= feistel_function(right);
	}

	left  ^= pbox[16];
	right ^= pbox[17];
	swap(left, right);
}

void
blowfish_decrypt(uint32_t *left, uint32_t *right)
{
	int i;
	for (i = 16; i > 0; i -= 2) {
		left  ^= pbox[i + 1];
		right ^= feistel_function(left);
		right ^= pbox[i];
		left  ^= feistel_function(right);
	}

	left  ^=  pbox[1];
	right ^= pbox[0];
	SWAP(left, right);
}

void
blowfish_engine(uint8_t *left, uint8_t *right, uint8_t *key)
{
	int keylen = strlen(key), i;
	uint32_t left = 0, right = 0;

	for (i = 0; i < 18; i++) {
		pbox[i] ^= key[i % keylen] | key[(i + 1) % keylen] | 
		           key[(i + 2) % keylen] | key[(i + 3) % keylen];
	}

	for (i = 0; i < 18; i += 2) {
		blowfish_encrypt(left, right);
		pbox[i]     = left;
		pbox[i + 1] = right;
	}

	for (i = 0; i < 5; i++) {
		for (j = 0; j < 256; j += 2) {
			blowfish_encrypt(left, right);
			sbox[i][j]     = left;
			sbox[i][j + 1] = right;
		}
	}
}

void
blowfish_start(uint8_t *data)
{

}