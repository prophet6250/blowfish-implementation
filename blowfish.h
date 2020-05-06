#ifndef __BLOWFISH__
#define __BLOWFISH__

/* utility macros */
#define SWAP(x, y) (x) += (y); (y) = (x) - (y); (x) -= (y);

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

uint32_t 
gen_subkey(uint32_t arg);

void 
blowfish_encrypt(uint32_t *left, uint32_t *right);

void
blowfish_decrypt(uint32_t *left, uint32_t *right);

uint8_t *
blowfish_initialize(uint8_t data_array[], uint8_t key[]);

#endif