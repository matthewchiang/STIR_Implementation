#include <stdio.h>
#include <string.h>
//#include <openssl/sha.h>
#include <openssl/ec.h>

const int SIZEOFOBUFF = 32;

int main(int argc, char** argv) {

	
/*	SHA256_CTX *c;
	if (SHA256_Init(c) == 0) {
		printf("error in SHA init\n");
	}
*/


	if (argc < 3) {
		printf("usage: %s privateKey msg", argv[0]);
	}

	char *privateKey = argv[1];
	unsigned char *mess =  argv[2];
//	unsigned char hashVal[SIZEOFOBUFF];
	unsigned char *hashVal;


//	SHA256(argv[1], strlen(argv[1]), hashVal);
	hashVal = ecies_encrypt(privateKey, mess, strlen(mess));


	int i;
	for(i = 0; i < SIZEOFOBUFF; i++) {
		printf("%02x ", hashVal[i]);
	}
	printf("\n");


	
//	printf("%s\n", hashVal); //prints as unsigned chars


}



