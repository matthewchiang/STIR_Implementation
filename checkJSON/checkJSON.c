#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include "cJSON.h"


const char* typ = "passport";
const char* alg = "ES256";
const char* x5u = "https://www.example.com/cert.cer";
const long iat = 1443208345;
const char* origtn = "12155551212";
const char* desttn = "12155551213";

void base64encode(char*, int, char*, int*);
void base64decode(char*, int, char*, int*);

char* sign_example();
void verify_example(char*);


int main() {

	char* jws;
	jws = sign_example();

	verify_example(jws);


	/*
	cJSON *hdr = cJSON_CreateObject();
	cJSON *pay = cJSON_CreateObject();

	cJSON_AddStringToObject(hdr, "typ", typ);
	cJSON_AddStringToObject(hdr, "alg", alg);
	cJSON_AddStringToObject(hdr, "x5u", x5u);

	cJSON *orig = cJSON_CreateObject();
	cJSON *dest = cJSON_CreateObject();

	cJSON_AddStringToObject(orig, "tn", origtn);
	cJSON_AddStringToObject(dest, "tn", desttn);

	cJSON_AddItemToObject(pay, "orig", orig);
	cJSON_AddItemToObject(pay, "dest", dest);
	cJSON_AddNumberToObject(pay, "iat", iat);




	char* b64pay_str;
	int b64pay_len;
	char* b64hdr_str;
	int b64hdr_len;

	base64encode((char*)pay, sizeof(pay), b64pay_str, &b64pay_len);

	printf("b64pay str: %s\n", b64pay_str);
	*/




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
}

void base64decode(char* src_buf, int src_len, char* tgt_buf, int* tgt_len) {
	int pos, i, n;
	unsigned char c[4];
	for (pos=0, i=0, *tgt_len=0; pos < src_len; pos++) {
		if (src_buf[pos] >= 'A' && src_buf[pos] <= 'Z')
			c[i] = src_buf[pos] - 65;   /* <65..90>  --> <0..25> */
		else if (src_buf[pos] >= 'a' && src_buf[pos] <= 'z')
			c[i] = src_buf[pos] - 71;   /* <97..122>  --> <26..51> */
		else if (src_buf[pos] >= '0' && src_buf[pos] <= '9')
			c[i] = src_buf[pos] + 4;    /* <48..56>  --> <52..61> */
		else if (src_buf[pos] == '+')
			c[i] = 62;
		else if (src_buf[pos] == '/')
			c[i] = 63;
		else  /* '=' */
			c[i] = 64;
		i++;
		if (pos == src_len-1) {
			while (i < 4) {
				c[i] = 64;
				i++;
			}
		}
		if (i==4) {
			if (c[0] == 64)
				n = 0;
			else if (c[2] == 64)
				n = 1;
			else if (c[3] == 64)
				n = 2;
			else
				n = 3;
			switch (n) {
				case 3:
					tgt_buf[*tgt_len+2] = (char) (((c[2] & 0x03) << 6) | c[3]);
					/* no break */
				case 2:
					tgt_buf[*tgt_len+1] = (char) (((c[1] & 0x0F) << 4) | (c[2] >> 2));
					/* no break */
				case 1:
					tgt_buf[*tgt_len+0] = (char) ((c[0] << 2) | (c[1] >> 4));
					break;
			}
			i=0;
			*tgt_len+= n;
		}
	}
}



char* sign_example() {

	printf("in sign\n");

	//simple base64 encode test
	char* encodestr_pay = "{\"dest\":{\"uri\":[\"sip:alice@example.com\"]},\"iat\":1471375418,\"orig\":{\"tn\":\"12155551212\"}}";
	int encodelen_pay = strlen(encodestr_pay);
	char* outstr_pay = (char*)malloc(256);
	int outlen_pay = 0;
	char* encodestr_hdr = "{\"alg\":\"ES256\",\"typ\":\"passport\",\"x5u\":\"https://cert.example.org/passport.cer\"}";
	int encodelen_hdr = strlen(encodestr_hdr);
	char* outstr_hdr = (char*)malloc(256);
	int outlen_hdr = 0;

	base64encode(encodestr_pay, encodelen_pay, outstr_pay, &outlen_pay);

	printf("outstr_pay: %s\n", outstr_pay);
	printf("outlen_pay: %i\n", outlen_pay);	


	base64encode(encodestr_hdr, encodelen_hdr, outstr_hdr, &outlen_hdr);

	printf("outstr_hdr: %s\n", outstr_hdr);
	printf("outlen_hdr: %i\n", outlen_hdr);	

	//create plaintext = hdr . pay
	char* plainJWS = (char*)malloc(outlen_pay+outlen_hdr+1);
	strcat(strcat(strcpy(plainJWS, outstr_hdr), "."), outstr_pay);

	printf("printing hdr . pay: %s\n", plainJWS);

	//get priv key
	FILE *fp_priv = fopen("priv.pem", "r");
	if (!fp_priv) {
		printf("no priv\n");
		exit(1);
	}
	EC_KEY *eckey = PEM_read_ECPrivateKey(fp_priv, NULL, NULL, NULL);
	if (!eckey) {
		printf("no eckey\n");
	}
	if (fclose(fp_priv)) printf("can't close file\n");


	//hash
	char* hashJWS = (char*)malloc(32);
	SHA256(plainJWS, strlen(plainJWS), hashJWS);

	//sign
	ECDSA_SIG *sig = (ECDSA_SIG *)malloc(128);
	sig = ECDSA_do_sign(hashJWS, 32, eckey);	

	//extract r and s
//	printf("r hex: %s\n", BN_bn2hex(sig->r));
//	printf("s hex: %s\n", BN_bn2hex(sig->s));
//	printf("r dec: %s\n", BN_bn2dec(sig->r));
//	printf("s dec: %s\n", BN_bn2dec(sig->s));

	//extract as octects
	uint8_t* to_r = (uint8_t*)malloc(32);
	uint8_t* to_s = (uint8_t*)malloc(32);

	BN_bn2bin(sig->r, to_r);
	BN_bn2bin(sig->s, to_s);
	

	//jws = r || s
	uint8_t* r_and_s = (uint8_t*)malloc(64);
	strcat(strcpy(r_and_s, to_r), to_s);
	int r_and_s_len = strlen(r_and_s);

	//print r || s
	{
		int i = 0;
		for (i = 0; i < strlen(r_and_s); i++) {
			printf("%i ", r_and_s[i]);
		}	
		printf("\n");

		printf("printing len of r || s: %i\n", r_and_s_len);
	}

	//base64(jws)
	char* outstr_jws = (char*)malloc(256);
	int outlen_jws = 0;

	base64encode(r_and_s, r_and_s_len, outstr_jws, &outlen_jws);

	printf("printing base64 jws: %s\n", outstr_jws);

	free(r_and_s);
	free(to_s);
	free(to_r);
	free(sig);
	free(hashJWS);
	free(plainJWS);
	free(outstr_hdr);
	free(outstr_pay);

	return outstr_jws;

}

void verify_example(char* jws) {


	printf("\n\nin verify\n");


	printf("printing base64 jws: %s\n", jws);

	//char* r_and_s = (char*)malloc(256);
	//int r_and_s_len = 0;

	//base64decode(jws, strlen(jws), r_and_s, &r_and_s_len);

	//split r_and_s into r ; s

	//get public key

	//	EC_KEY *eckey = EVP_PKEY_get1_EC_KEY();


	free(jws);


}
