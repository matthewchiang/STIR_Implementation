#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

const int SIZEOFOBUFF = 32;

int main(int argc, char** argv) {

	
/*	SHA256_CTX *c;
	if (SHA256_Init(c) == 0) {
		printf("error in SHA init\n");
	}
*/


	unsigned char mess[] =  "hello world"; //default message

	unsigned char hashVal[SIZEOFOBUFF];

	if (argc == 1) {
		SHA256(mess, strlen(mess), hashVal);
	}
	else {
		SHA256(argv[1], strlen(argv[1]), hashVal);
	}


	int i;
	for(i = 0; i < SIZEOFOBUFF; i++) {
		printf("%02x ", hashVal[i]);
	}
	printf("\n");
	
//	printf("%s\n", hashVal);


}



