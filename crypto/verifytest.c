#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ec.h> //init eliptic curve
#include <openssl/ecdsa.h> //sign and verify
#include <openssl/objects.h> //for sn2nid (curve name to id)
#include <openssl/bn.h>

const int DGST_LEN = 32; //sha256 return size
const char* CURVE_TYPE = "secp256k1";

/*
uint8_t pub_bytes65[65] = {
	0x04,
	0x6e, 0x7b, 0x03, 0x77, 0x07, 0xb4, 0xa4, 0x8a, 
	0xcf, 0x38, 0x81, 0xbe, 0x2b, 0xb1, 0x3c, 0xfc, 
	0x95, 0x11, 0x05, 0x2e, 0xff, 0x9d, 0xd4, 0x03, 
	0xab, 0x2c, 0x8e, 0x5b, 0xd5, 0x7d, 0xd9, 0x37,
	0x87, 0xb5, 0x74, 0x37, 0xa1, 0xd4, 0xdc, 0x36, 
	0x50, 0xce, 0xa9, 0x8b, 0xae, 0x21, 0x7d, 0x5d, 
	0xe0, 0xb3, 0x64, 0x51, 0xcf, 0x21, 0xf2, 0x91, 
	0xd9, 0x87, 0x63, 0x7c, 0x3b, 0xf2, 0x5e, 0x9d
};
*/

uint8_t pub_bytes[33] = {
	0x03,
	0x6e, 0x7b, 0x03, 0x77, 0x07, 0xb4, 0xa4, 0x8a,
	0xcf, 0x38, 0x81, 0xbe, 0x2b, 0xb1, 0x3c, 0xfc,
	0x95, 0x11, 0x05, 0x2e, 0xff, 0x9d, 0xd4, 0x03,
	0xab, 0x2c, 0x8e, 0x5b, 0xd5, 0x7d, 0xd9, 0x37
};

uint8_t der_bytes[] = {
	0x30, 0x44,
	0x02, 0x20,
	0x1c, 0x37, 0x99, 0x3c, 0xdd, 0x09, 0x39, 0x0d, 
	0x41, 0x8e, 0xf3, 0xbf, 0x78, 0x06, 0xc9, 0x45, 
	0x9a, 0xdc, 0x7e, 0xa7, 0x05, 0xfc, 0xba, 0x98, 
	0x44, 0xe7, 0x3c, 0xc2, 0xa5, 0x99, 0x45, 0xb8,
	0x02, 0x20,
	0x71, 0x3e, 0x16, 0xe0, 0xfc, 0xd7, 0xc5, 0x94, 
	0x25, 0xb9, 0x36, 0x7e, 0x29, 0x6c, 0x66, 0xd6, 
	0x49, 0x1a, 0x70, 0x56, 0x70, 0xcc, 0x2a, 0x63, 
	0xaf, 0xd3, 0xa4, 0x36, 0x32, 0x15, 0xa1, 0x89
};


/*
//file format is private key in hex separated by colons
char* readBytesFromPublicKey(char* filepath) {

	char* ret;
	long length;

	FILE *fp;
	fp = fopen(filepath, "r");
	if (fp == NULL) {
		printf("can't open file\n");
		exit(-1);
	}

	fseek(fp, 0, SEEK_END); //go to end to file file length
	length = ftell(fp);

	if(length == 0) {
		printf("empty file\n");
		exit(-1);
	}

	fseek(fp, 0, SEEK_SET); //go back to beginning
	ret = malloc(length);
	fread(ret, 1, length, fp); //read 'length' bytes

	//ret is 64B key separated by colons = 95B
	printf("printing str:\n%s\n", ret); 

	fclose(fp);
	return ret;

}
*/





int main(int argc, char** argv) {


 	/*
 	uint8_t pub_bytes[33] = {
        0x02,
        0x82, 0x00, 0x6e, 0x93, 0x98, 0xa6, 0x98, 0x6e,
        0xda, 0x61, 0xfe, 0x91, 0x67, 0x4c, 0x3a, 0x10,
        0x8c, 0x39, 0x94, 0x75, 0xbf, 0x1e, 0x73, 0x8f,
        0x19, 0xdf, 0xc2, 0xdb, 0x11, 0xdb, 0x1d, 0x28
    };

    uint8_t der_bytes[] = {
        0x30, 0x44, 
        0x02, 0x20, 
        0x2b, 0x2b, 0x52, 0x9b, 0xdb, 0xdc, 0x93, 0xe7,
        0x8a, 0xf7, 0xe0, 0x02, 0x28, 0xb1, 0x79, 0x91,
        0x8b, 0x03, 0x2d, 0x76, 0x90, 0x2f, 0x74, 0xef,
        0x45, 0x44, 0x26, 0xf7, 0xd0, 0x6c, 0xd0, 0xf9, 
        0x02, 0x20, 
        0x62, 0xdd, 0xc7, 0x64, 0x51, 0xcd, 0x04, 0xcb, 
        0x56, 0x7c, 0xa5, 0xc5, 0xe0, 0x47, 0xe8, 0xac, 
        0x41, 0xd3, 0xd4, 0xcf, 0x7c, 0xb9, 0x24, 0x34, 
        0xd5, 0x5c, 0xb4, 0x86, 0xcc, 0xcf, 0x6a, 0xf2
    };
    */

/*
	if (argc < 3) {
		printf("usage: %s publicKey msg\n", argv[0]);
		exit(0);
	}
*/

	//get public key from file
	//uint8_t *pubKeyBytes = pub_bytes;//readBytesFromPublicKey(argv[1]);
	//note: sizeof pub_bytes = 33 ; sizeof pubKeyBytes = 8

	//initializing eckey object

	int curve_NID = OBJ_sn2nid(CURVE_TYPE);
	EC_KEY *eckey = EC_KEY_new_by_curve_name(curve_NID);

	const uint8_t *pubKeyBytes_copy = pub_bytes;
	o2i_ECPublicKey(&eckey, &pubKeyBytes_copy, sizeof(pub_bytes));

	if (!eckey) {
		printf("error in eckey\n");
		exit(2);
	}

    

	//end init eckey

	//set sig
	
	const uint8_t *der_bytes_copy = der_bytes;
	ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &der_bytes_copy, sizeof(der_bytes));

    printf("r      : %s\n", BN_bn2hex(sig->r));
    printf("s      : %s\n", BN_bn2hex(sig->s));


	//hash message


	uint8_t dgst[DGST_LEN];
	//char* message = argv[2];
	char* message = "msg\n";
	SHA256(message, strlen(message), dgst);

	printf("successfully hashed\n");

	//debug: print hash
	printf("printing hash: ");
	{
		int i;
		for (i = 0; i < DGST_LEN; i++)
		printf("%02x", dgst[i]);
		printf("\n");
	}
	


	//verifying******************************************************************************

	int verified = ECDSA_do_verify(dgst, sizeof(dgst), sig, eckey);
	printf("verified: %i\n", verified);

	if (verified == 1) { printf("correct!\n"); }
	else if (verified == 0) { printf("incorrect!\n"); }
	else printf("error with verification\n");


	return 0;


}

