#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>


const char* typ = "passport";
const char* alg = "ES256";
const char* x5u = "https://www.example.com/cert.cer";
const long iat = 1443208345;
const char* origtn = "12155551212";
const char* desttn = "12155551213";

void base64encode(char*, int, char*, int*);
void base64decode(char*, int, char*, int*);

//char* sign_example();
// void verify_example(char*);


int main(int argc, char *argv[]) {

	
	if (argc < 2) {
		printf("usage: b64sig\n");
		//printf("usage: sig, x5u, iat, orig, dest\n");
		exit(0);
	}


	//calculate signature = b64 decode (argv[1])
	char* jws = (char*)malloc(256);
	int jws_len = 0;
	base64decode(argv[1], strlen(argv[1]), jws, &jws_len);

	printf("decoded jws: %s\n", jws);
	printf("size (should be 64): %i\n", strlen(jws));
	

//XXX
/*
	const unsigned char* jws_copy = jws;
	ECDSA_SIG *sig = ECDSA_SIG_new();
	if (!(d2i_ECDSA_SIG(&sig, &jws_copy, jws_len))) {
		printf("failure creating sig\n");
		exit(1);
	}
*/

	//get public key
	X509 *cert;
	EVP_PKEY *pubkey;
	EC_KEY *eckey;
	unsigned char *buf;
	long buflen;

	buflen = 

//  from pem:
//	BIO *bio = BIO_new(BIO_s_file());

//	if (!(BIO_read_filename(bio, "cert.der"))) { 
//		printf("can't read filename\n");
//		exit(1);
//	}

//	if (!(cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) ) {
//		printf("error in read bio x509\n");
//		exit(2);
//	}
	
	if (!(cert = d2i_x509(NULL, , ))) {
		printf("error in d2i x509\n");
		exit(2);
	}

	if (!(pubkey = X509_get_pubkey(cert)) ) {
		printf("error in pubkey\n");
		exit(3);
	}

	if (!(eckey = EVP_PKEY_get1_EC_KEY(pubkey)) ) {
		printf("error in eckey\n");
		exit(4);
	}

	BIO_free(bio);
	X509_free(cert);
	EVP_PKEY_free(pubkey);	



	//r and s from signature
	char *r, *s;
	memcpy(jws, 32, r);
	memcpy(jws+32, 32, s);


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
	char* toHash = (char*)malloc(outlen_pay+outlen_hdr+1);
	strcat(strcat(strcpy(toHash, outstr_hdr), "."), outstr_pay);

	printf("printing hdr . pay: %s\n", toHash);
	printf("len hdr.pay: %i\n", strlen(toHash));


	//hash
	char* hashedJWS = (char*)malloc(32);
	SHA256(toHash, strlen(toHash), hashedJWS);


	//verify...
	int8_t verified = ECDSA_verify(0, hashedJWS, strlen(hashedJWS), jws, jws_len, eckey);
	printf("verified: %i\n", verified);


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

