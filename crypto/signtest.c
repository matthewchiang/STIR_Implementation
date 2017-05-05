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

uint8_t priv_bytes[32] = {
	0x14, 0x76, 0x31, 0x76, 0x93, 0x7c, 0x98, 0x75, 
	0x04, 0xed, 0x0e, 0xaf, 0x33, 0x2b, 0x35, 0x3a,
	0x30, 0x3e, 0x46, 0xc2, 0xda, 0xb8, 0xb4, 0xae,
	0x88, 0xdc, 0x98, 0xc2, 0x06, 0x1d, 0x7d, 0x34
};


/*
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
*/



int main(int argc, char** argv) {


/*
	if (argc < 3) {
		printf("usage: %s privateKey msg\n", argv[0]);
		exit(0);
	}
*/
	//uint8_t *privKeyBytes = priv_bytes; //readBytesFromPrivateKey(argv[1]);

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


	//reuse existing private key
	BIGNUM *priv = BN_new();
	BN_bin2bn(priv_bytes, sizeof(priv_bytes), priv); //private key is 32B
	if (!EC_KEY_set_private_key(eckey, priv)) {
		printf("failed to set private key\n");
		exit(2);
	}
	
	//generate public key
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	const EC_GROUP *group = EC_KEY_get0_group(eckey);
	EC_POINT *pub = EC_POINT_new(group);
	EC_POINT_mul(group, pub, priv, NULL, NULL, ctx); //calculate point and set as pub key
	EC_KEY_set_public_key(eckey, pub);

	printf("successfully created eckey\n");



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
		printf("%02x ", dgst[i]);
		printf("\n");
	}


	//signing********************************************************************************

	ECDSA_SIG *sig; //either store as sig or in char buffer
	size_t sig_len;
	uint8_t *sigDerBuff, *buff_copy;

	sig = ECDSA_do_sign(dgst, sizeof(dgst), eckey);

	printf("r: %s\n", BN_bn2hex(sig->r));
    printf("s: %s\n", BN_bn2hex(sig->s));

	sig_len = ECDSA_size(eckey); //= 72B
	sigDerBuff = calloc(sig_len, sizeof(uint8_t));
	buff_copy = sigDerBuff;
	i2d_ECDSA_SIG(sig, &buff_copy);


	{
		int i;
		for (i = 0; i < sig_len; i++)
			printf("%02x ", sigDerBuff[i]);
		printf("\n");
	}


	//write to file
	FILE *fp;
	fp = fopen("sigOut.txt", "w");
	int i;
	for (i = 0; i < sig_len; i++) {
		fprintf(fp, "%02x ", sigDerBuff[i]);
	}
	fclose(fp);

	//verifying******************************************************************************

/*
	int ret;
	uint8_t *verBuff;
	verBuff = sigDerBuff;
	if (!(ret = ECDSA_verify(0, dgst, DGST_LEN, verBuff, sig_len, eckey))) {
		printf("verifcation failed!\n");
	}

	printf("Printing return: %i\n", ret);

	if (ret == 1) { printf("correct!\n"); }
	else if (ret == 0) { printf("incorrect!\n"); }
	else printf("error with ret\n");
*/

	return 0;


}

