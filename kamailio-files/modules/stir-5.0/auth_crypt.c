/*
 * $Id$
 *
 * Copyright (c) 2007 iptelorg GmbH
 *
 * This file is part of sip-router, a free SIP server.
 *
 * sip-router is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * sip-router is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*!
 * \file
 * \brief SIP-router auth-identity :: Crypt
 * \ingroup auth-identity
 * Module: \ref auth-identity
 */


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#include <openssl/x509_vfy.h>

#include "../../core/mem/mem.h"
#include "../../core/parser/parse_uri.h"

#include "auth_identity.h"

int retrieve_x509(X509 **pcert, str *scert, int bacceptpem)
{
	BIO *bcer=NULL;
	char serr[160];
	int iRet=0;


	if (!(bcer=BIO_new(BIO_s_mem()))) {
		LOG(L_ERR, "STIR module:retrieve_x509: Unable to create BIO\n");

		return -1;
	}

	do {
		if (BIO_write(bcer, scert->s, scert->len)!=scert->len) {
			LOG(L_ERR, "STIR module:retrieve_x509: Unable to write BIO\n");
			iRet=-2;
			break;
		}

		/* RFC 4474 only accepts certs in the DER form but it can not harm
		 * to be a little bit more flexible and accept PEM as well. */
		if (bacceptpem
		  	&& scert->len > BEGIN_PEM_CERT_LEN
			&& memmem(scert->s,
					  scert->len,
					  BEGIN_PEM_CERT,
					  BEGIN_PEM_CERT_LEN)) {
			if (!(*pcert = PEM_read_bio_X509(bcer, NULL, NULL, NULL))) {
				ERR_error_string_n(ERR_get_error(), serr, sizeof(serr));
				LOG(L_ERR, "STIR module:retrieve_x509: PEM Certificate %s\n", serr);
				iRet=-4;
			}
		} else {
			if (!(*pcert = d2i_X509_bio(bcer, NULL))) {
				ERR_error_string_n(ERR_get_error(), serr, sizeof(serr));
				LOG(L_ERR, "STIR module:retrieve_x509: DER Certificate %s\n", serr);
				iRet=-3;
			}
		}
	} while (0);

	BIO_free(bcer);

	return iRet;
}

int check_x509_subj(X509 *pcert, str* sdom)
{
	STACK_OF(GENERAL_NAME) *altnames;
	int ialts, i1, ilen, altlen;
	const GENERAL_NAME *actname;
	char scname[AUTH_DOMAIN_LENGTH];
	char *altptr;
	struct sip_uri suri;
	int ret = 0;


	/* we're looking for subjectAltName for the first time */
	altnames = X509_get_ext_d2i(pcert, NID_subject_alt_name, NULL, NULL);

	if (altnames) {
		ialts = sk_GENERAL_NAME_num(altnames);

		for (i1=0; i1 < ialts; i1++) {
			actname = sk_GENERAL_NAME_value(altnames, i1);

			if (actname->type == GEN_DNS || actname->type == GEN_URI) {
				/* we've found one */
#if OPENSSL_VERSION_NUMBER >= 0x010100000L
				altptr = (char *)ASN1_STRING_get0_data(actname->d.ia5);
#else
				altptr = (char *)ASN1_STRING_data(actname->d.ia5);
#endif
				if (actname->type == GEN_URI) {
					if (parse_uri(altptr, strlen(altptr), &suri) != 0) {
						continue;
					}
					if (!(suri.type == SIP_URI_T || suri.type == SIPS_URI_T)) {
						continue;
					}
					if (suri.user.len != 0 || suri.passwd.len != 0) {
						continue;
					}
					altptr = suri.host.s;
					altlen = suri.host.len;
				} else {
					altlen = strlen(altptr);
				}
				if (sdom->len != altlen 
					|| strncasecmp(altptr, sdom->s, sdom->len)) {
					LOG(L_INFO, "STIR module: VERIFIER: subAltName of certificate doesn't match host name\n");
					ret = -1;
				} else {
					ret = 1;
					break;
				}
			}
		}
		GENERAL_NAMES_free(altnames);
	}

	if (ret != 0) {
		return ret == 1 ? 0 : ret;
 	}

	/* certificate supplier host and certificate subject match check */
	ilen=X509_NAME_get_text_by_NID (X509_get_subject_name (pcert),
									NID_commonName,
									scname,
									sizeof (scname));
	if (sdom->len != ilen || strncasecmp(scname, sdom->s, sdom->len)) {
		LOG(L_INFO, "STIR module: VERIFIER: common name of certificate doesn't match host name\n");
		return -2;
	}

	return 0;
}

int verify_x509(X509 *pcert, X509_STORE *pcacerts)
{
	X509_STORE_CTX *ca_ctx = NULL;
	char *strerr;

	ca_ctx = X509_STORE_CTX_new();
	if(ca_ctx==NULL) {
		LM_ERR("cannot get a x509 context\n");
		return -1;
	}

	if (X509_STORE_CTX_init(ca_ctx, pcacerts, pcert, NULL) != 1) {
		LOG(L_ERR, "STIR module:verify_x509: Unable to init X509 store ctx\n");
		X509_STORE_CTX_free(ca_ctx);
		return -1;
	}

	if (X509_verify_cert(ca_ctx) != 1) {
		strerr = (char *)X509_verify_cert_error_string(X509_STORE_CTX_get_error(ca_ctx));
		LOG(L_ERR, "STIR module: VERIFIER: Certificate verification error: %s\n", strerr);
		X509_STORE_CTX_cleanup(ca_ctx);
		X509_STORE_CTX_free(ca_ctx);
		return -2;
	}
	X509_STORE_CTX_cleanup(ca_ctx);
	X509_STORE_CTX_free(ca_ctx);

	LOG(AUTH_DBG_LEVEL, "STIR module: VERIFIER: Certificate is valid\n");

	return 0;
}



//************************************************************** START EC **********************************************************************/



//input: inputstr, privkey
//output: sencb64 = base64(sign(hash(inputstr)))
int ec_sign(dynstr *inputstr, dynstr *sencb64, EC_KEY *ec_privkey) {

    //hash message, store as dgst
    char* dgst = (char*)malloc(SHA256_DIGEST_LENGTH + 1);
    SHA256((unsigned char*)getstr_dynstr(inputstr).s, getstr_dynstr(inputstr).len, dgst);

    //sign dgst
	ECDSA_SIG *sig = (ECDSA_SIG *)malloc(128);
    sig = ECDSA_do_sign((unsigned char*)dgst, strlen(digest), ec_privkey);

    char* to_r = (char*)malloc(32);
	char* to_s = (char*)malloc(32);
	BN_bn2bin(sig->r, (uint8_t*)to_r);
	BN_bn2bin(sig->s, (uint8_t*)to_s);

	char* r_and_s = (char*)malloc(64);
	strcat(strcpy(r_and_s, to_r), to_s);
	int r_and_s_len = strlen(r_and_s);

	//base64 signature
	char* outstr_jws = (char*)malloc(256);
	int outlen_jws = 0;

	base64encode(r_and_s, r_and_s_len, outstr_jws, &outlen_jws);

	//add b64(sign) to sencb64 to return
	resetstr_dynstr(sencb64);
	str add;
	add.s = outstr_jws;
	add.len = outlen_jws;
	if (app2dynstr(sencb64,&add)) {
		LOG(L_ERR, "STIR: ec_sign: error -1\n");
		return -1;
	}

    return 0;

}



//sencedsha is signed passport
//ssha is hashed passport
//ishalen = 32B
int ec_verify(char *sencedsha, int iencedshalen, char *ssha, int sshasize, int *ishalen, X509 *pcertx509) {

	EVP_PKEY *pkey;
	EC_KEY *eckey;
	unsigned long lerr;
	char serr[160];

	pkey=X509_get_pubkey(pcertx509);
	if (pkey == NULL) {
		lerr=ERR_get_error(); ERR_error_string_n(lerr, serr, sizeof(serr));
		LOG(L_ERR, "STIR module:decrypt_identity: Pubkey %s\n", serr);
		return -1;
	}

	X509_free(pcertx509);

	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	EVP_PKEY_free(pkey);
	if (eckey == NULL) {
		LOG(L_ERR, "STIR module:decrypt_identity: Error getting EC key\n");
		return -2;
	}


    //set sig

    const uint8_t *signedsha_copy = (uint8_t*)sencedsha;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &signedsha_copy, iencedshalen);

    //verifying

    int verified = ECDSA_do_verify((uint8_t*)ssha, sshasize, sig, eckey);

    if (verified == 1) { 
		//correct
		return 0;
	}
    else if (verified == 0) { 
		LOG(L_ERR, "invalid signature\n");
		return -3;
	}
    else {
		LOG(L_ERR, "error in verification\n");
		return -4;
	}


}


//************************************************************** END EC ********************************************************************/




/* copypasted from ser/modules/rr/avp_cookie.c + this adds '=' sign! ) */
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


/* copypasted from ser/modules/rr/avp_cookie.c */
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

int x509_get_validitytime(time_t *tout, ASN1_UTCTIME *tin)
{
	char *sasn1;
	int i1;
	struct tm tmptm;


	memset(&tmptm, 0, sizeof(tmptm));
	i1=tin->length;
	sasn1=(char *)tin->data;

	if (i1 < 10)
		return -1;
/*	if (sasn1[i1-1]!='Z')
		return -1;*/
	for (i1=0; i1<10; i1++)
		if((sasn1[i1] > '9') || (sasn1[i1] < '0'))
			return -2;

	tmptm.tm_year=(sasn1[0]-'0')*10+(sasn1[1]-'0');
	if(tmptm.tm_year < 50)
		tmptm.tm_year+=100;

	tmptm.tm_mon=(sasn1[2]-'0')*10+(sasn1[3]-'0')-1;
	if((tmptm.tm_mon > 11) || (tmptm.tm_mon < 0))
		return -3;

	tmptm.tm_mday=(sasn1[4]-'0')*10+(sasn1[5]-'0');
	tmptm.tm_hour= (sasn1[6]-'0')*10+(sasn1[7]-'0');
	tmptm.tm_min=(sasn1[8]-'0')*10+(sasn1[9]-'0');

	if ((sasn1[10] >= '0') && (sasn1[10] <= '9') &&
		   (sasn1[11] >= '0') && (sasn1[11] <= '9'))
		tmptm.tm_sec=(sasn1[10]-'0')*10+(sasn1[11]-'0');

#ifdef HAVE_TIMEGM
	*tout=timegm(&tmptm);
#else
	*tout=_timegm(&tmptm);
#endif

	return 0;
}

int x509_get_notbefore(time_t *tout, X509 *pcert)
{
	return (x509_get_validitytime(tout, X509_get_notBefore(pcert)));
}

int x509_get_notafter(time_t *tout, X509 *pcert)
{
	return (x509_get_validitytime(tout, X509_get_notAfter(pcert)));
}
