# BLOWFISH ENCRYPTION ALGORITHM
My Implementation of the 64-bit Blowfish Cryptographic block cipher

**This is(never was) not meant to be used in production code, nor as a source of reference**. 
This was purely a programming excercise. Mistakes & vulnerabilities are bound to creeep into this code. 
So don't use this code in professional environments.

# REQUIREMENTS
My machine has `GCC version 9.2.0`. Although, any C compiler, with support of ISO C11 may be used 
to compile this code, preferably GCC version 4.9+

# COMPILE AND RUN
`gcc blowfish.c main.c -o ./blow -lm`

`./blow`

# HOW TO CHANGE PREDEFINED INPUTS
Inside `main.c`, there are two macro definitions, namely `#define PLAINTEXT` and `#define KEY`. 
Edit these values with your own custom plaintext and key values. Keep in mind, keysize should not 
be greater than 56 characters (preferable less than 55).

# RESOURCES USED
1. https://morf.lv/introduction-to-data-encryption (basic feistel cipher and then Blowfish using Qt and C++)
