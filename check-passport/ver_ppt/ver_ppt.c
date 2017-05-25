#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/x509.h>
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
	printf("jws_len (should be 64): %i\n", jws_len);
	


	//r and s from signature
	char *r, *s;
	memcpy(r, jws, 32);
	memcpy(s, jws+32, 32);

	BIGNUM *bn_r = BN_bin2bn(r, 32, NULL);
	BIGNUM *bn_s = BN_bin2bn(s, 32, NULL);

	ECDSA_SIG *sig = ECDSA_SIG_new();
	sig->r = bn_r;
	sig->s = bn_s;


	// get public key
	X509 *cert;
	EVP_PKEY *pubkey;
	EC_KEY *eckey;
	unsigned char *buf;
	long buflen;
	FILE *fp;

	// open file
	fp = fopen("cert.der", "r");
	if (!fp) {
		printf("no fp");
		exit(1);
	}	

	// obtain file size:
	fseek (fp, 0, SEEK_END);
	buflen = ftell(fp);
	rewind(fp);

	// copy into buffer
	buf = (unsigned char*)malloc(sizeof(char)*buflen);
	size_t copyResult = fread(buf, 1, buflen, fp);
	if (copyResult != buflen) {
		printf("didn't copy same number of bytes\n");
		exit(2);
	}
	const unsigned char *const_buf_cpy = buf;
	
	// extract public key
	if (!(cert = d2i_X509(NULL, &const_buf_cpy, buflen))) {
		printf("error in d2i x509\n");
		exit(3);
	}

	if (!(pubkey = X509_get_pubkey(cert)) ) {
		printf("error in pubkey\n");
		exit(4);
	}

	if (!(eckey = EVP_PKEY_get1_EC_KEY(pubkey)) ) {
		printf("error in eckey\n");
		exit(5);
	}

	X509_free(cert);
	EVP_PKEY_free(pubkey);	
	free(buf);
	fclose(fp);




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
	unsigned char* hashedJWS = (char*)malloc(32);
	SHA256(toHash, strlen(toHash), hashedJWS);

	//verify...
	//dgst, dgstlen, sig, siglen, key


	//int8_t verified = ECDSA_verify(0, hashedJWS, 32, sig, siglen, eckey);
	int8_t verified = ECDSA_do_verify(hashedJWS, 32, sig, eckey);
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

