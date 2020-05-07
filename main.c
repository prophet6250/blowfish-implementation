#include <stdio.h>
#include <string.h>

#include "blowfish.h"

#define KEYSIZE  56
#define DATASIZE 1024

void
print_error()
{
	printf("Usage: bfsh [Options] FileName\n"
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
	
	j = 1;
	/* parsing the command line flags */
	while (j < argc) {
		/* encryption mode */
		if (!strncmp(argv[j], "-e", 2)) 
		{
			if (!(dataF = fopen(argv[j + 1], "r+"))) {
				printf("file not found!\nmake sure the file"
				       " exists in the program's root directory"
				       "\n");
				return 1;
			}
			printf("data file for encryption read\n");
			
			cryptF = fopen(argv[j + 2], "w+");
			printf("crypt file created for encryption\n");

			/* reading from the data file */
			i = 0;
			while (!feof(dataF)) {
				character = fgetc(dataF);

				printf("%x", character);
				data[i] = character;
				i += 1;
			}
			
			clearerr(dataF);
			printf("\nreading from the datafile done\n");
			/* operation mode 0 means encryption mode */
			op_mode = 0;

			j += 3;
		}
		/* decryption mode */
		else if (!strncmp(argv[j], "-d", 2)) {
			if (!(dataF = fopen(argv[j + 1], "r+"))) {
				printf("file not found!\nmake sure the file"
				       " exists in the program's root directory"
				       "\n");
				return 1;
			}
			printf("data file for decryption read\n");

			
			cryptF = fopen(argv[j + 2], "w+");

			/* reading from the data file */
			i = 0;
			while (!feof(dataF)) {
				character = fgetc(dataF);

				printf("%x", character);
				data[i] = character;
				i += 1;
			}
			
			clearerr(dataF);
			printf("\nreading from the datafile done\n");
			/* operation mode 1 means decryption mode */
			op_mode = 1;

			j += 3;
		}
		/* key file source */
		else if (!strncmp(argv[j], "-k", 2)) {
			if (!(keyF = fopen(argv[j + 1], "r"))) {
				printf("file not found!\nmake sure the file"
				       " exists in the program's root directory"
				       "\n");
				return 1;
			}
			printf("key file read\n");

			
			/* reading from the key file */
			i = 0;
			while (!feof(keyF)) {
				character = fgetc(keyF);
				
				printf("%x", character);
				key[i] = character;
				i += 1;
			}
			
			clearerr(keyF);
			printf("\nreading from the keyfile done\n");

			j += 2;
		}
		/* wrong choice, dude */
		else {
			print_error();
			return 1;
		}
	}

	crypt_data = blowfish_initialize(data, key, op_mode);
	fputs(crypt_data, cryptF);
	printf("\nwriting to the encrypted file done\n");
	i = 0;
	while (i < strlen(data)) {
		printf("%x", crypt_data[i]);
		i += 1;
	}
	printf("\n");
	clearerr(cryptF);

	fclose(dataF);
	fclose(keyF);
	fclose(cryptF);

	return 0;
}