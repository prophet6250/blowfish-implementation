#include <stdio.h>
#include <string.h>

#include "blowfish.h"

#define KEYSIZE  56
#define DATASIZE 4096

/* hep message */
void
print_error()
{
	printf("Usage: bfsh [Options] FileName(s)\n"
	       "Options:\n  -e\tencrypt mode->enter src file name and encrypted"
	       " file name after this flag\n  -d\tdecrypt mode->enter decrypted"
	       " file name and data file name after this flag\n  -k\tkey" 
	       " file->enter the filename containing the keys"
	       " after this flag\n  -h\tprint this help message\n");
	printf("\nSample usage: ./bfsh -e source.txt source.encrypt -k key.txt"
	       "\n");
}

int main(int argc, char const *argv[])
{
	int i, j;
	uint8_t data[DATASIZE], key[KEYSIZE];
	uint8_t character, op_mode = 0;
	uint8_t *crypt_data;
	FILE *dataF, *keyF, *cryptF;
	
	if (!strncmp(argv[1], "-h", 2)) {
		print_error();
		return 1;
	}
	
	if (argc < 6) {
		printf("ERROR : INSUFFICIENT ARGUMENTS SUPPLIED!\n\n");
		print_error();
		return 1;
	}

	j = 1;
	while (j < argc) {
		if (!strncmp(argv[j], "-e", 2)) {
			if (!(dataF = fopen(argv[j + 1], "rb+"))) {
				printf("file not found!\nmake sure the file"
				       " exists in the program's root directory"
				       "\n");
				return 1;
			}
			
			cryptF = fopen(argv[j + 2], "wb+");

			/* reading from the data file */
			i = 0;
			while (!feof(dataF)) {
				character = fgetc(dataF);

				printf("%x", character);
				data[i] = character;
				i += 1;
			}
			
			printf("\nreading from the datafile done\n");
			/* operation mode 0 means encryption mode */
			op_mode = 0;

			j += 3;
		}
		else if (!strncmp(argv[j], "-d", 2)) {
			if (!(dataF = fopen(argv[j + 1], "rb+"))) {
				printf("file not found!\nmake sure the file"
				       " exists in the program's root directory"
				       "\n");
				return 1;
			}
			
			cryptF = fopen(argv[j + 2], "wb+");

			/* reading from the data file */
			i = 0;
			while (!feof(dataF)) {
				character = fgetc(dataF);

				printf("%x", character);
				data[i] = character;
				i += 1;
			}
			
			printf("\nreading from the datafile done\n");
			/* operation mode 1 means decryption mode */
			op_mode = 1;

			j += 3;
		}
		else if (!strncmp(argv[j], "-k", 2)) {
			if (!(keyF = fopen(argv[j + 1], "r"))) {
				printf("file not found!\nmake sure the file"
				       " exists in the program's root directory"
				       "\n");
				return 1;
			}
			
			/* reading from the key file */
			i = 0;
			while (!feof(keyF)) {
				character = fgetc(keyF);
				
				printf("%x", character);
				key[i] = character;
				i += 1;
			}
			
			printf("\nreading from the keyfile done\n");
			
			/* initialize with the key first */
			blowfish_init(key);

			j += 2;
		}
		else {
			printf("ERROR : INVALID FLAG ENTERED!\n\n");
			print_error();
			return 1;
		}
	}

	
	
	/* then run the encryption or decryption */
	if (op_mode) {
		crypt_data = blowfish_decrypt(data);
	}
	else {
		crypt_data = blowfish_encrypt(data);
	}

	fputs(crypt_data, cryptF);
	printf("\nwriting to the crypt file done\n");
	
	/* printing the crypt data for verification */
	i = 0;
	while (i < strlen(data)) {
		printf("%x", crypt_data[i]);
		i += 1;
	}
	printf("\n");

	fclose(dataF);
	fclose(keyF);
	fclose(cryptF);

	return 0;
}
