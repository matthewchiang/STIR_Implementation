#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>

const char* CURVE_TYPE = "prime256v1";

const char* typ = "passport";
const char* alg = "ES256";
const char* x5u = "https://www.example.com/cert.cer";
const long iat = 1443208345;
const char* origtn = "12155551212";
const char* desttn = "12155551213";

void base64encode(char*, int, char*, int*);
void base64decode(char*, int, char*, int*);

void sign_example();
// void verify_example(char*);


int main() {

	//char* b64jws;

	sign_example();

	//verify_example(b64jws);



	return 0;


}



void base64encode(char* src_buf, int src_len, char* tgt_buf, int* tgt_len) {
	static char code64[64+1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int pos;
	for (pos=0, *tgt_len=0; pos < src_len; pos+=3,*tgt_len+=4) {
		tgt_buf[*tgt_len+0] = code64[(unsigned char)src_buf[pos+0] >> 2];
		tgt_buf[*tgt_len+1] = code64[(((unsigned char)src_buf[pos+0] & 0x03) << 4) | ((pos+1 < src_len)?((unsigned char)src_buf[pos+1] >> 4):0)];
		if (pos+1 < src_len)
			tgt_buf[*tgt_len+2] = code64[(((unsigned char)src_buf[pos+1] & 0x0F) << 2) | ((pos+2 < src_len)?((unsigned char)src_buf[pos+2] >> 6):0)];
		else
			tgt_buf[*tgt_len+2] = '=';
		if (pos+2 < src_len)
			tgt_buf[*tgt_len+3] = code64[(unsigned char)src_buf[pos+2] & 0x3F];
		else
			tgt_buf[*tgt_len+3] = '=';
	}

	//now take out = padding ...
	if (tgt_buf[*tgt_len-2] == '=') {
		tgt_buf[*tgt_len-2] = 0;
		*tgt_len -= 2;	
	}
	else if (tgt_buf[*tgt_len-1] == '=') {
		tgt_buf[*tgt_len-1] = 0;
		*tgt_len -= 1;
	}
}


//char* encodestr_pay = "{\"dest\":{\"uri\":[\"sip:alice@example.com\"]},\"iat\":1471375418,\"orig\":{\"tn\":\"12155551212\"}}";
//char* encodestr_hdr = "{\"alg\":\"ES256\",\"typ\":\"passport\",\"x5u\":\"https://cert.example.org/passport.cer\"}";


void sign_example() {


	//hdr
	char* encodestr_hdr = "{\"alg\":\"ES256\",\"typ\":\"passport\",\"x5u\":\"matthewchiang.github.io/STIR/rpi3_ec_prime256v1_cert.der\"}";
	int encodelen_hdr = strlen(encodestr_hdr);
	char* outstr_hdr = (char*)malloc(256);
	int outlen_hdr = 0;

	base64encode(encodestr_hdr, encodelen_hdr, outstr_hdr, &outlen_hdr);

	printf("outstr_hdr: %s\n", outstr_hdr);
	printf("outlen_hdr: %i\n", outlen_hdr);	


	//pay
	char* encodestr_pay = "{\"dest\":{\"uri\":[\"sip:recv3@10.0.0.180\"]},\"iat\":1495176051,\"orig\":{\"uri\":[\"sip:send3@10.0.0.180\"]}}";
	int encodelen_pay = strlen(encodestr_pay);
	char* outstr_pay = (char*)malloc(256);
	int outlen_pay = 0;

	base64encode(encodestr_pay, encodelen_pay, outstr_pay, &outlen_pay);

	printf("outstr_pay: %s\n", outstr_pay);
	printf("outlen_pay: %i\n", outlen_pay);	



	//create plaintext = hdr . pay
	char* plainJWS = (char*)malloc(outlen_pay+outlen_hdr+2);
	strcat(strcat(strcpy(plainJWS, outstr_hdr), "."), outstr_pay);

	printf("\nprinting 'hdr . pay' : %s\n", plainJWS);
	printf("len of 'hdr . pay' : %i\n", strlen(plainJWS));


	//hash
	char* hashJWS = (char*)malloc(256);
	SHA256(plainJWS, strlen(plainJWS), hashJWS);

	printf("\nlength of hashed text (should be 32 = output of SHA256): %i\n", strlen(hashJWS));


	//get priv key
	FILE *fp_priv = fopen("priv.pem", "r");
	if (!fp_priv) {
		printf("no priv\n");
		exit(1);
	}
	int curve_NID = OBJ_sn2nid(CURVE_TYPE);
	EC_KEY *eckey = EC_KEY_new_by_curve_name(curve_NID);
	eckey = PEM_read_ECPrivateKey(fp_priv, NULL, NULL, NULL);
	if (!eckey) {
		printf("no eckey\n");
	}
	if (fclose(fp_priv)) printf("can't close file\n");


	//sign
	ECDSA_SIG *sig = (ECDSA_SIG *)malloc(128);
	sig = ECDSA_do_sign(hashJWS, strlen(hashJWS), eckey);	

	//extract r and s as octect arrays
	uint8_t* to_r = (uint8_t*)malloc(32);
	uint8_t* to_s = (uint8_t*)malloc(32);

	BN_bn2bin(sig->r, to_r);
	BN_bn2bin(sig->s, to_s);
	

	//jws = r || s
	//NOTE: INT ARRAY, NOT STRING
	//0 value is okay
	uint8_t* r_cat_s = (uint8_t*)malloc(64); //r and s are 32 bytes each
	memcpy(r_cat_s, to_r, 32);
	memcpy(r_cat_s + 32, to_s, 32);	
	int r_cat_s_len = 64;


	//debug:
	//print r || s
	/*
	{
		int i = 0;
		for (i = 0; i < 32; i++) {
			printf("%i ", to_r[i]);
		}	
		for (i=0; i < 32; i++) {
			printf("%i ", to_s[i]);
		}
		printf("\n");
	}

	//print r_cat_s
	{
		int i;
		for (i=0; i < 64; i++) {
			printf("%i ", r_cat_s[i]);
		}
		printf("\n");

	}
	*/


	//base64(jws)
	char* outstr_jws = (char*)malloc(128);
	int outlen_jws = 0;

	base64encode(r_cat_s, r_cat_s_len, outstr_jws, &outlen_jws);

	printf("\nprinting base64 jws: %s\n", outstr_jws);
	printf("printing base64 jws len (should be 86): %i\n", outlen_jws);

	free(r_cat_s);
	free(to_s);
	free(to_r);
	free(sig);
	free(hashJWS);
	free(plainJWS);
	free(outstr_hdr);
	free(outstr_pay);
	
	free(outstr_jws);

	//return outstr_jws;

}
