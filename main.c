#include <stdio.h>
#include <string.h>

#include "blowfish.h"

#define FILENAME "file.text"
#define FILESIZE 1024
#define KEYSIZE  56

int main(int argc, char const *argv[])
{
	FILE *file = fopen(FILENAME, "r+");
	uint8_t key[KEYSIZE];
	printf("enter the encryption key for the file\n");
	scanf("%s", &key);

	return 0;
}