#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ec.h> //init eliptic curve
#include <openssl/ecdsa.h> //sign and verify
#include <openssl/objects.h> //for sn2nid (curve name to id)
#include <openssl/bn.h>
//#include <openssl/err.h> //for debugging errors

const int DGST_LEN = 32; //sha256 return size
const char* CURVE_TYPE = "secp256k1";



//file format is private key in hex separated by colons
char* readBytesFromPrivateKey(char* filepath) {

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




int main(int argc, char** argv) {



	if (argc < 3) {
		printf("usage: %s privateKey msg\n", argv[0]);
		exit(0);
	}

	char *privKeyBytes = readBytesFromPrivateKey(argv[1]);

	//initializing eckey object to desired curve type

	EC_KEY *eckey;
	int curve_NID = OBJ_sn2nid(CURVE_TYPE);
	eckey = EC_KEY_new_by_curve_name(curve_NID);
	if (eckey == NULL) {
		printf("error in eckey\n");
		exit(2);
	}


/*
	//generate new key pair
	if (!EC_KEY_generate_key(eckey)) {
		printf("error in ec key gen\n");
		exit(2);
	}
*/



	//reuse old key
	BIGNUM *priv = BN_new();
	BN_bin2bn(privKeyBytes, 32, priv); //private key is 32B
	if (!EC_KEY_set_private_key(eckey, priv)) {
		printf("failed to set private key\n");
		exit(2);
	}
	
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	const EC_GROUP *group = EC_KEY_get0_group(eckey);
	EC_POINT *pub = EC_POINT_new(group);
	EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);
	EC_KEY_set_public_key(eckey, pub);


	printf("successfully created eckey\n");



	//hash first

	unsigned char dgst[DGST_LEN];
	SHA256(argv[2], strlen(argv[2]), dgst);

	printf("successfully hashed\n");

	//debug: print hash
	printf("printing hash: ");
	{
		int i;
		for (i = 0; i < DGST_LEN; i++)
		printf("%02x ", dgst[i]);
		printf("\n");
	}


	//signing********************************************************************************

	//ECDSA_SIG *sig; //either store as sig or in char buffer
	unsigned char *sigBuff;
	int buf_len;
	buf_len = ECDSA_size(eckey); // = 72B

	sigBuff = OPENSSL_malloc(buf_len);
	if (!ECDSA_sign(0, dgst, DGST_LEN, sigBuff, &buf_len, eckey)) {
		printf("failed in sign\n");
		exit(2);
	}

	
	//write to file
	FILE *fp;
	fp = fopen("sigOut.txt", "w");
	int i;
	for (i = 0; i < buf_len; i++) {
		fputc(sigBuff[i], fp);
	}
	fclose(fp);


	//verifying******************************************************************************


	int ret;
	unsigned char *verBuff;
	verBuff = sigBuff;
	if (!(ret = ECDSA_verify(0, dgst, DGST_LEN, verBuff, buf_len, eckey))) {
		printf("verifcation failed!\n");
	}

	printf("Printing return: %i\n", ret);

	if (ret == 1) { printf("correct!\n"); }
	else if (ret == 0) { printf("incorrect!\n"); }
	else printf("error with ret\n");


	return 0;


}

