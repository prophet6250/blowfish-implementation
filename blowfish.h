#ifndef __BLOWFISH__
#define __BLOWFISH__

/* integer overflow isn't an issue here */
#define SWAP(x, y, temp) {temp = (x); (x) = (y); (y) = temp;}

/* shorthand typedefs. a full  header file for such a thing is an overkill */
typedef unsigned char          uint8_t;
typedef unsigned int           uint32_t;
typedef unsigned long long int uint64_t;

uint32_t 
feistel_function(uint32_t arg);

void 
_encrypt(uint32_t *left, uint32_t *right);

void
_decrypt(uint32_t *left, uint32_t *right);

void
blowfish_init(uint8_t key[], int padsize);

uint8_t *
blowfish_encrypt(uint8_t data[], int padsize);

uint8_t *
blowfish_decrypt(uint8_t crypt_data[], int padsize);

#endif
