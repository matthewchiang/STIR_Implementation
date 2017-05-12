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
 * \brief SIP-router auth-identity :: Module interface
 * \ingroup auth-identity
 * Module: \ref auth-identity
 */

/*! \defgroup auth-identity SIP-router SIP identity support
 *
 * Auth Identity module provides functionalities for securely identifying
 * originators of SIP messages. This module has two basic service:
 *   - authorizer - authorizes a message and adds Identity and Identity-Info headers
 *   - verifier - verifies an authorized message
 *
 */


#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include "../../core/dprint.h"
#include "../../core/ut.h"
#include "../../core/sr_module.h"
#include "../../core/mem/mem.h"
#include "../../core/parser/parse_from.h"
#include "../../core/parser/parse_cseq.h"
#include "../../core/parser/parse_content.h"
#include "../../core/parser/parse_uri.h"
#include "../../core/parser/contact/parse_contact.h"
#include "../../core/timer.h"

#include "auth_identity.h"

MODULE_VERSION;

static int mod_init(void); /* Module initialization function */
static void mod_deinit(void);
static int get_certificate(struct sip_msg* msg, char* srt1, char* str2);
static int check_validity(struct sip_msg* msg, char* srt1, char* str2);
static int check_date(struct sip_msg* msg, char* srt1, char* str2);
static int check_callid(struct sip_msg* msg, char* srt1, char* str2);
static int check_certificate(struct sip_msg* msg, char* srt1, char* str2);
static int date_proc(struct sip_msg* msg, char* srt1, char* str2);
static int add_identity(struct sip_msg* msg, char* srt1, char* str2);

void callid_gc(unsigned int tick, void *param);

/*
 * Module parameter variables
 */
char	*glb_sprivkeypath="";	/* private key of the authentication service */
char 	*glb_sservercerturl="";	/* URL of the certificate of the authentication service */
char 	*glb_sservercertpath=""; /* Path of the certificate of the authentication service */
int		glb_icertlimit=CERTIFICATE_TABLE_ITEM_LIMIT;
char	*glb_scainfo="";
int		glb_iauthval=AUTH_MSG_VALIDITY_TIME;	/* Message validity time in seconds (verification service)*/
int		glb_imsgtime=AUTH_MSG_TO_AUTH_VALIDITY_TIME;	/* Message validity time in seconds (authentication service)*/
int 	glb_icallidlimit=CALLID_TABLE_ITEM_LIMIT;

CURL 	*glb_hcurl;		/* global cURL handle */
X509 	*glb_pcertx509=NULL;
X509_STORE *glb_cacerts=NULL;

EC_KEY *glb_ecprivkey=NULL;

time_t	glb_imycertnotafter=0;

int 	glb_authservice_disabled=0;
int 	glb_acceptpem=0;

dynstr	glb_sdgst={{0,0},0}; /* Digest string */
dynstr	glb_sidentity={{0,0},0}; /* Identity message header */
dynstr	glb_sdate={{0,0},0}; /* Date  message header */
dynstr	glb_b64encedmsg={{0,0},0}; /* buffer for base64, ec signed string */

ttable *glb_tcert_table=0;				/* Certificate Table */
char glb_certisdownloaded=0;
tcert_item glb_tcert={{0,0},{0,0},0};	/* Actually Used Certificate */

ttable *glb_tcallid_table=0;			/* Certificate Table */
typedef struct timeparams { /* sturct of the callid garbage collector */
	int ibnow;	/* the actual bucket we've not checked yet */
	int ibnum;  /* number of the buckets we've to check */
	int ibcir;  /* timer function's called this times during the whole table check */
} ttimeparams;
ttimeparams glb_ttimeparams={0,0,0};


/*
 * Exported functions
 */
static cmd_export_t glb_cmds[] = {
	{"auth_date_proc", date_proc, 0, 0, REQUEST_ROUTE},
	{"auth_add_identity", add_identity, 0, 0, REQUEST_ROUTE},
	{"vrfy_get_certificate", get_certificate, 0, 0, REQUEST_ROUTE},
	{"vrfy_check_msgvalidity", check_validity, 0, 0, REQUEST_ROUTE},
	{"vrfy_check_certificate", check_certificate, 0, 0, REQUEST_ROUTE},
	{"vrfy_check_date", check_date, 0, 0, REQUEST_ROUTE},
	{"vrfy_check_callid", check_callid, 0, 0, REQUEST_ROUTE},
	{0, 0, 0, 0, 0}
};


/*
 * Exported parameters
 */
static param_export_t glb_params[] = {
	{"privatekey_path", 		PARAM_STRING,	&glb_sprivkeypath},
	{"certificate_url", 		PARAM_STRING,	&glb_sservercerturl},
	{"certificate_cache_limit", PARAM_INT, 		&glb_icertlimit},
	{"callid_cache_limit",		PARAM_INT, 		&glb_icallidlimit},
	{"certificate_path", 		PARAM_STRING,	&glb_sservercertpath},
	{"auth_validity_time",		PARAM_INT,    	&glb_iauthval},
	{"msg_timeout", 			PARAM_INT, 		&glb_imsgtime},
	{"cainfo_path", 			PARAM_STRING, 	&glb_scainfo},
	{"accept_pem_certs", 		PARAM_INT,		&glb_acceptpem},
	{0, 0, 0}
};


/*
 * Module interface
 */
struct module_exports exports = {
	"stir",
	glb_cmds,   /* Exported functions */
	0,          /* RPC methods */
	glb_params, /* Exported parameters */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_deinit, /* destroy function */
	0,          /* oncancel function */
	0			/* child initialization function */
};


static int mod_init(void)
{
	CURLcode iRet;
	FILE *hpemfile;
	char serr[160];
	X509 *pmycert=NULL;		/* certificate of the authentication service */
	time_t tnow, ttmp;

	/*
	 *
	 * Parameter check
	 *
	 */
	if (glb_sprivkeypath[0]==0) {
		LOG(L_WARN, "STIR:mod_init: Private key path is missing! Authorization service is disabled\n");
		glb_authservice_disabled=1;
	}
	if (!glb_authservice_disabled && glb_sservercerturl[0]==0) {
		LOG(L_WARN, "STIR:mod_init: URL of certificate of the server is missing! Authorization service is disabled\n");
		glb_authservice_disabled=1;
	}
	if (!glb_authservice_disabled && glb_sservercertpath[0]==0) {
		LOG(L_WARN, "STIR:mod_init: Path of certificate of the server is missing! Authorization service is disabled\n");
		glb_authservice_disabled=1;
	}

	/*
	 *
	 * Init the curl session and download buffer
	 *
	 */
	curl_global_init(CURL_GLOBAL_ALL);
	if ((glb_hcurl=curl_easy_init())==NULL) {
		LOG(L_ERR, "STIR:mod_init: Unable to init cURL library!\n");
		return -1;
	}
	/* send all data to this function  */
	if ((iRet=curl_easy_setopt(glb_hcurl, CURLOPT_WRITEFUNCTION, curlmem_cb))!=0) {
		LOG(L_ERR,
			"STIR:mod_init: Unable to set cURL write function option: %s\n",
			curl_easy_strerror(iRet));
		return -2;
	}
	/* we pass our 'glb_tcert' struct to the callback function */
	if ((iRet=curl_easy_setopt(glb_hcurl, CURLOPT_WRITEDATA, (void *)&glb_tcert.scertpem))!=0) {
		LOG(L_ERR,
			"STIR:mod_init: Unable to set cURL writedata option: %s\n",
			curl_easy_strerror(iRet));
		return -4;
	}
	if (!(glb_tcert.scertpem.s=pkg_malloc(CERTIFICATE_LENGTH))) {
		LOG(L_ERR, "STIR:mod_init: Not enough memory error\n");
		return -3;
	}
  	/* some servers don't like requests that are made without a user-agent
	   field, so we provide one */
	if ((iRet=curl_easy_setopt(glb_hcurl, CURLOPT_USERAGENT, "ser-agent/1.0"))!=0) {
		LOG(L_WARN,
			"AUTH_IDENTITY:mod_init: Unable to set cURL useragent option: %s\n",
			curl_easy_strerror(iRet));
	}
	if ((iRet=curl_easy_setopt(glb_hcurl, CURLOPT_SSL_VERIFYPEER, 1))!=0) {
		LOG(L_WARN,
			"AUTH_IDENTITY:mod_init: Unable to set cURL verifypeer option: %s\n",
			curl_easy_strerror(iRet));
	}
	if ((iRet=curl_easy_setopt(glb_hcurl, CURLOPT_SSL_VERIFYHOST, 2))!=0) {
		LOG(L_WARN,
			"AUTH_IDENTITY:mod_init: Unable to set cURL verifyhost option: %s\n",
			curl_easy_strerror(iRet));
	}

	/* cainfo_path module parameter's been set */
	if (glb_scainfo[0]) {
		if ((iRet=curl_easy_setopt(glb_hcurl, CURLOPT_CAINFO, glb_scainfo))!=0) {
			LOG(L_WARN,
				"AUTH_IDENTITY:mod_init: Unable to set cURL cainfo option: %s\n",
				curl_easy_strerror(iRet));
		}
	}


	/*
	 *
	 * OpenSSL certificate verification initialization
	 *
	 */
	OpenSSL_add_all_algorithms();
	if (!(glb_cacerts=X509_STORE_new())) {
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: unable to initialize X509 store\n");
		return -16;
	}
	if (X509_STORE_set_default_paths(glb_cacerts)!=1) {
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: unable to set X509 store default path\n");
		return -17;
	}
	if (glb_scainfo[0]
		   && X509_STORE_load_locations(glb_cacerts, glb_scainfo, NULL) != 1)
		LOG(L_WARN, "AUTH_IDENTITY:mod_init: unable to load X509 store location\n");


	/*
	 *
	 * Init the Date, Digest-String, and Identity
	 *
	 */
	if (initdynstr(&glb_sdgst, DGST_STR_INIT_SIZE))
		return -5;

	/*
	 * Init certificate table
	 */
	if (init_table(&glb_tcert_table,
				   CERTIFICATE_TABLE_ENTRIES,
				   glb_icertlimit,
				   cert_item_cmp,
				   cert_item_init,
				   cert_item_least,
				   cert_item_free,
				   NULL))
 		return -5;

	/*
	 * Init call-id table
	 */
	if (init_table(&glb_tcallid_table,
				   CALLID_TABLE_ITEM_LIMIT,
				   glb_icallidlimit,
				   cid_item_cmp,
				   cid_item_init,
				   cid_item_least,
				   cid_item_free,
				   cid_item_gc))
		return -5;

	glb_ttimeparams.ibnow=0;
	/* we've to check the whole table in glb_imsgtime, so the number of
	   buckets we've to check in every timer call is
	   CALLID_TABLE_ENTRIES/glb_imsgtime/CALLID_GARBAGE_COLLECTOR_INTERVAL */
	glb_ttimeparams.ibcir=glb_iauthval/CALLID_GARBAGE_COLLECTOR_INTERVAL;
	if (!glb_ttimeparams.ibcir)
		glb_ttimeparams.ibcir=1;
	glb_ttimeparams.ibnum=CALLID_TABLE_ENTRIES/glb_ttimeparams.ibcir;

	if (register_timer(callid_gc, (void*)&glb_ttimeparams /* param*/, CALLID_GARBAGE_COLLECTOR_INTERVAL  /* period */) < 0 ) {
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: Can not register timer\n");
		return -5;
	}

	/*
	 * If there were not enough parameter set then we could not initialize
	 * the authorizer part
	 */
	if (glb_authservice_disabled)
		return 0;

	//for auth service only:

	if (initdynstr(&glb_sidentity, DGST_STR_INIT_SIZE)) // = 8*1024
		return -6;

	if (initdynstr(&glb_sdate, AUTH_TIME_LENGTH)) // =64
		return -7;


	/*
  	 * Get my certificate
	 */
	if (!(hpemfile=fopen(glb_sservercertpath, "r"))) {
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: unable to open certificate '%s'\n", strerror(errno));
		return -12;
	}
	if (!(pmycert=PEM_read_X509(hpemfile, NULL, NULL, NULL))) {
		ERR_error_string_n(ERR_get_error(), serr, sizeof serr);
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: '%s'\n", serr);
		fclose(hpemfile);
		return -13;
	}
	if (x509_get_notafter(&glb_imycertnotafter, pmycert)) {
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: Error getting certificate expiration date\n");
		return -13;
	}
	if (x509_get_notbefore(&ttmp, pmycert)) {
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: Error getting certificate validity date\n");
		return -13;
	}
	if ((tnow=time(0)) < 0) {
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: time error %s\n", strerror(errno));
		return -13;
	}
	if (tnow < ttmp || tnow > glb_imycertnotafter) {
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: Date of certificate is invalid (%s)\n", glb_sservercertpath);
		return -14;
	}

	if (fclose(hpemfile))
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: unable to close file\n");
	X509_free(pmycert);

	/*
 	 * Init EC-SHA256 encoder
	 * Previously RSA-SHA1
	 */

	//open file with priv key
	hpemfile=fopen(glb_sprivkeypath, "r");
	if (!hpemfile)
	{
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: unable to open private key '%s'\n", strerror(errno));
		return -12;
	}

	// Get EC key
	glb_ecprivkey = PEM_read_ECPrivateKey(hpemfile, NULL, NULL, NULL);
	if (!glb_ecprivkey) {
		ERR_error_string_n(ERR_get_error(), serr, sizeof serr);
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: '%s'\n", serr);
		fclose(hpemfile);
		return -13;
	}

	//close file
	if (fclose(hpemfile))
		LOG(L_ERR, "AUTH_IDENTITY:mod_init: unable to close file\n");


	// init buffer for base64(sign(hash(msg)))
	if (initdynstr(&glb_b64encedmsg, B64_MSG_SIZE))
		return -17;

	return 0;
} // end mod_init()


static void mod_deinit(void)
{
	curl_easy_cleanup(glb_hcurl);
	if (glb_tcert.scertpem.s)
		pkg_free(glb_tcert.scertpem.s);
	free_dynstr(&glb_sdgst);
	xfree_dynstr(&glb_sidentity);
	free_dynstr(&glb_sdate);
	free_dynstr(&glb_b64encedmsg);
 	free_table(glb_tcert_table);
	free_table(glb_tcallid_table);

	if (glb_cacerts)
		X509_STORE_free(glb_cacerts);
} //end mod_deinit()


/*
 *
 *	VERIFIER FUNCTIONS
 *
 */


// 1.) check_date()
// 2.) get_certificate()
// 3.) check_certificate()
// 4.) check_msg_validity()
// 5.) check_callid()


/*
 * The Date header must indicate a time within 60 seconds of the receipt of a message
 */
static int check_date(struct sip_msg* msg, char* srt1, char* str2)
{
	time_t tnow, tmsg;
	int ires;

	//check that date header exists
	ires=datehdr_proc(NULL, NULL, msg);
	if (ires)
		return -1;

#ifdef HAVE_TIMEGM
	tmsg=timegm(&get_date(msg)->date);
#else
	tmsg=_timegm(&get_date(msg)->date);
#endif
	if (tmsg < 0) {
		LOG(L_ERR, "AUTH_IDENTITY:check_date: timegm error\n");
		return -2;
	}

	if ((tnow=time(0)) < 0) {
		LOG(L_ERR, "AUTH_IDENTITY:check_date: time error %s\n", strerror(errno));
		return -3;
	}

	if (tnow > tmsg + glb_iauthval) {
		LOG(L_INFO, "AUTH_IDENTITY VERIFIER: Outdated date header value (%ld sec)\n", tnow - tmsg + glb_iauthval);
		return -4;
	} else
		LOG(AUTH_DBG_LEVEL, "AUTH_IDENTITY VERIFIER: Date header value OK\n");

	return 1;
}



static int get_certificate(struct sip_msg* msg, char* srt1, char* str2)
{

/*
	//extract URL from msg
	if (identityinfohdr_proc(&glb_tcert.surl, NULL, msg))
		return -3;

	// we support rsa-sha1 only (alg.len==0 then we use rsa-sha1)
	//NOTE: changed to sha256 instead
	if (get_identityinfo(msg)->alg.len
		&& (get_identityinfo(msg)->alg.len != strlen("rsa-sha256")
		    || strncasecmp("rsa-sha256",
							get_identityinfo(msg)->alg.s,
							get_identityinfo(msg)->alg.len ))) {
		LOG(L_ERR, "AUTH_IDENTITY:get_certificate: Unsupported Identity-Info algorithm\n");
		return -5;
	}
*/

	if (getURLFromIdentity(&glb_tcert.surl, msg)) {
		return -3;
	}

	// this case ivalidbefore==0 shows that this certificate was downloaded
	glb_tcert.ivalidbefore=0;

	// check whether this certificate is our certificate table
	if (get_cert_from_table(glb_tcert_table, &glb_tcert.surl, &glb_tcert)) {
		// we did not found it in the table, so we've to download it
		// we reset the PEM buffer
		glb_tcert.scertpem.len=0;
		if (download_cer(&glb_tcert.surl, glb_hcurl))
			return -6;
		glb_certisdownloaded=1;
	} else
		glb_certisdownloaded=0;

	if (retrieve_x509(&glb_pcertx509, &glb_tcert.scertpem, glb_acceptpem))
		return -7;


	return 1;
}


int check_certificate(struct sip_msg* msg, char* srt1, char* str2) {
	struct sip_uri tfrom_uri;
	str suri;

	if (!glb_pcertx509) {
		LOG(L_ERR, "AUTH_IDENTITY:check_certificate: Certificate uninitialized! (has vrfy_get_certificate been called?)\n");
		return -1;
	}
	/* this certificate was downloaded so we've to verify and add it to table */
	if (glb_certisdownloaded) {
		if (fromhdr_proc(&suri, NULL, msg))
			return -1;

		if (parse_uri(suri.s, suri.len, &tfrom_uri)) {
			LOG(L_ERR, "AUTH_IDENTITY:get_certificate: Error while parsing FROM URI\n");
			return -2;
		}

		if (verify_x509(glb_pcertx509, glb_cacerts))
			return -3;

		if (check_x509_subj(glb_pcertx509, &tfrom_uri.host))
			return -4;

		/* we retrieve expiration date from the certificate (it needs for
		   certificate table garbage collector) */
		if (x509_get_notafter(&glb_tcert.ivalidbefore, glb_pcertx509))
			return -5;

		if (addcert2table(glb_tcert_table, &glb_tcert))
			return -6;
	}
	return 1;
}



/*
 * If the digest-string, assembled from the message, corresponds to the string
 * decoded from the Identity header by the acquired public key then the message
 * is valid. RFC 4474 [6] Step 3
 */
static int check_validity(struct sip_msg* msg, char* srt1, char* str2)
{
	str sidentity;
	char sencedsha[HASH_STR_SIZE]; // 1024
	int iencedshalen;
#ifndef NEW_RSA_PROC
	char ssha[HASH_STR_SIZE];
#endif
	int ishalen;
	unsigned char sstrcrypted[SHA256_DIGEST_LENGTH];
	int iRet=1;


	if (!glb_pcertx509) {
		LOG(L_ERR, "AUTH_IDENTITY:check_validity: Certificate uninitialized! (has vrfy_get_certificate been called?)\n");
		return -1;
	}

	do {
		/* get the value of identity header parsed */
		if (identityhdr_proc(&sidentity, NULL, msg)) {
			iRet=-1;
			break;
		}

		/* the length of identity value should be 172 octets long */
		/* ?????? no set length in 4474bis b/c variable URL length
		if (sidentity.len > sizeof(sencedsha)) {
			LOG(L_ERR, "AUTH_IDENTITY:check_validity: Unexpected Identity length (%d)\n", sidentity.len);
			iRet=-2;
			break;
		}
		*/

		/* base64 decode the value of Identity header */
		base64decode(sidentity.s, sidentity.len, sencedsha, &iencedshalen);

		/* assemble the digest string to be able to compare it with decrypted one */
		if (digeststr_asm(&glb_sdgst, msg, NULL, AUTH_INCOMING_BODY)) {
		//if (assemble_passport(&glb_sdgst, msg, NULL, glb_tcert.surl))
			iRet=-5;
			break;
		}
		// calculate hash
		SHA256((unsigned char*)getstr_dynstr(&glb_sdgst).s,
			  getstr_dynstr(&glb_sdgst).len,
			  sstrcrypted);


#ifdef NEW_RSA_PROC
		/* decrypt with public key retrieved from the downloaded certificate
		   and compare it with the calculated digest hash */
/*
		if (rsa_sha256_dec(sencedsha, iencedshalen,
						 (char *)sstrcrypted, sizeof(sstrcrypted), &ishalen,
						 glb_pcertx509)) {
			iRet=-3;
			break;
		} else
			LOG(AUTH_DBG_LEVEL, "AUTH_IDENTITY VERIFIER: Identity OK\n");
*/

		if (ec_verify(sencedsha, iencedshalen,
						 (char *)sstrcrypted, sizeof(sstrcrypted), &ishalen,
						 glb_pcertx509)) {
			iRet=-3;
			break;
		} else
			LOG(AUTH_DBG_LEVEL, "AUTH_IDENTITY VERIFIER: Identity OK\n");


#else
		/* decrypt with public key retrieved from the downloaded certificate */
/*
		if (rsa_sha256_dec(sencedsha, iencedshalen,
						 ssha, sizeof(ssha), &ishalen,
						 glb_pcertx509)) {
			iRet=-3;
			break;
		}
*/

		if (ec_verify(sencedsha, iencedshalen,
						 ssha, sizeof(ssha), &ishalen,
						 glb_pcertx509)) {
			iRet=-3;
			break;
		}


		/* check hash size */
		if (ishalen != sizeof(sstrcrypted)) {
			LOG(L_ERR, "AUTH_IDENTITY:check_validity: Unexpected decrypted hash length (%d != %d)\n", ishalen, SHA256_DIGEST_LENGTH);
			iRet=-4;
			break;
		}
		/* compare hashes */
		if (memcmp(sstrcrypted, ssha, ishalen)) {
			LOG(L_INFO, "AUTH_IDENTITY VERIFIER: comparing hashes failed -> Invalid Identity Header\n");
			iRet=-6;
			break;
		} else
			LOG(AUTH_DBG_LEVEL, "AUTH_IDENTITY VERIFIER: Identity OK\n");
#endif
	} while (0);

	glb_pcertx509=NULL;

	return iRet;
}



static int check_callid(struct sip_msg* msg, char* srt1, char* str2)
{
	str scid, sftag, scseqnum;
	unsigned int ucseq;
	int ires;
	time_t ivalidbefore;


	if (callidhdr_proc(&scid, NULL, msg))
		return -1;

	if (cseqhdr_proc(&scseqnum, NULL, msg))
		return -2;
	if (str2int(&scseqnum, &ucseq))
		return -3;

	if (fromhdr_proc(NULL, &sftag, msg))
		return -4;

	if ((ivalidbefore=time(0)) < 0) {
		LOG(L_ERR, "AUTH_IDENTITY:check_callid: time error %s\n", strerror(errno));
		return -5;
	}

	ires=proc_cid(glb_tcallid_table,
				  &scid,
				  &sftag,
				  ucseq,
				  ivalidbefore + glb_iauthval);
	if (ires) {
		if (ires==AUTH_FOUND)
			LOG(L_INFO, "AUTH_IDENTITY VERIFIER: Call is replayed!\n");
		return -6;
	}

	return 1;
}


void callid_gc(unsigned int tick, void *param)
{
	/* check the last slice */
	if (((ttimeparams*)param)->ibnow + 1 == ((ttimeparams*)param)->ibcir) {
		garbage_collect(glb_tcallid_table,
						 (((ttimeparams*)param)->ibnow)*((ttimeparams*)param)->ibnum,
						 CALLID_TABLE_ENTRIES-1);
		/* we step to the first slice */
		((ttimeparams*)param)->ibnow=0;
	} else {
		garbage_collect(glb_tcallid_table,
						 (((ttimeparams*)param)->ibnow)*((ttimeparams*)param)->ibnum,
						 ((((ttimeparams*)param)->ibnow+1)*((ttimeparams*)param)->ibnum)-1);
		/* we step to the next slice */
		((ttimeparams*)param)->ibnow++;
	}
}


/*
 *
 *	AUTHORIZER FUNCTIONS: RFC4474bis Section 6.1
 *
 */

// 1.) Check Authority for the Identity
// 2.) Authenticate the Originator
// 3.) Verify Date is Present and Valid: date_proc()
// 4.) Population and Add the Identity Header: add_identity()
//			gets digest-string, calculates SHA256, signs with private key, base64 encode, add to message as Identity header


// Called in kamailio.cfg by auth_date_proc()
// Checks the Date header of the message
// Checks if Date within minute of current time and if certificate still valid
static int date_proc(struct sip_msg* msg, char* srt1, char* str2)
{
	str sdate;
	uint8_t iRes; // 0 to 3 enum for checking date exists
	time_t tmsg, tnow;

	if (glb_authservice_disabled) {
		LOG(L_WARN, "STIR:date_proc: Authentication Service is disabled\n");
		return -1;
	}

	getstr_dynstr(&glb_sdate).len=0;

	/* we'd like to get the DATE header of the message */
	iRes=datehdr_proc(&sdate, NULL, msg); //now sdate has date->body
	switch (iRes) {
		case AUTH_ERROR:
			return -2;

		// No date, so add current date
		case AUTH_NOTFOUND:
			if (append_date(&getstr_dynstr(&glb_sdate), glb_sdate.size, &tmsg, msg))
				return -3;
			break;

		// sip msg already has Date header, so we check that
		case AUTH_OK:
#ifdef HAVE_TIMEGM
			tmsg=timegm(&get_date(msg)->date);
#else
			tmsg=_timegm(&get_date(msg)->date);
#endif
			//tmsg, tnow = seconds since Epoch
			if (tmsg < 0) {
				LOG(L_ERR, "STIR:date_proc: timegm error\n");
				return -4;
			}
			if ((tnow=time(0))<0) {
				LOG(L_ERR, "STIR:date_proc: time error\n");
				return -5;
			}

			// If sipmsg time differs from current time by more than [glb_imsgtime], reject message
			// glb_imsgtime is parameter from .cfg w/ default of 60 seconds
			if (tmsg + glb_imsgtime < tnow || tnow + glb_imsgtime < tmsg) {
				LOG(L_INFO, "STIR:date_proc: Date header overdue\n");
				return -6;
			}

			break;
		default:
			/* unknown result */
			return -7;
	}

	/*
	 * The authentication service MUST verify that the Date header
	 * falls within the validity period of its certificate
	 * RFC 4474 [6] Step 3
	 */
	if (glb_imycertnotafter < tmsg) {
		LOG(L_INFO, "STIR:date_proc: My certificate has been expired\n");
		return -8;
	}

	return 1;
}

/*
 * Calculates JSON and places in digest-string, signs with the domain private-key,
 * BASE64 encodes that, and finally adds it to the message as the 'Identity'
 * header value
 */
static int add_identity(struct sip_msg* msg, char* srt1, char* str2)
{
	uint8_t iRes; // 0 to 3 enum for checking date exists
	str sstr; // for appending to digest str

	if (glb_authservice_disabled) {
		LOG(L_WARN, "STIR:add_identity: Authentication Service is disabled\n");
		return -1;
	}

	/* check Date */
	iRes=datehdr_proc(NULL, NULL, msg);
	switch (iRes) {
 		case AUTH_ERROR:
			return -2;

		// Just added date
		case AUTH_NOTFOUND:
			if (!getstr_dynstr(&glb_sdate).len) {
				/*
				 * date_proc() must be called before add_identity() because
				 * that function initializes the Date if that not exists
				 * in the SIP message
				 */
				LOG(L_ERR, "STIR:add_identity: Date header is not found (has auth_date_proc been called?)\n");
				return -3;
			}
			//  assemble the digest string and the DATE header is missing in the orignal message (add current date)
			if (digeststr_asm(&glb_sdgst, msg, &getstr_dynstr(&glb_sdate), AUTH_OUTGOING_BODY | AUTH_ADD_DATE))
			//if (assemble_passport(&glb_sdgst, msg, &getstr_dynstr(&glb_sdate), glb_sservercerturl))
				return -4;
			break;

		//Date exists: don't need to add new one
		default:
			//  assemble the digest string and the DATE header is available in the message
			if (digeststr_asm(&glb_sdgst, msg, NULL, AUTH_OUTGOING_BODY))
			//if (assemble_passport(&glb_sdgst, msg, NULL, glb_sservercerturl))
				return -5;
			break;
	}

	//old: glb_sdgst = all headers (not including identity)
	//new: glb_sdgst = base64 of PASSporTs

	// NOTE: compact form: only return JWS signature part
	// glb_b64encedmsg = base64(signed(hashed(msg)))
	if (ec_sign(&glb_sdgst, &glb_b64encedmsg, glb_ecprivkey))
		return -6;

	// we assemble the value of the Identity header
	// first part: Identity:[space]
	// second part: base64 msg
	// third part: [semicolon]info[equals]<
	// fourth part: cert URL
	// last part: >\r\n

	sstr.s="Identity: ";
	sstr.len=strlen("Identity: ");
	if (cpy2dynstr(&glb_sidentity, &sstr))
		return -7;

	if (app2dynstr(&glb_sidentity, &getstr_dynstr(&glb_b64encedmsg)))
		return -8;

	sstr.s=";info=<";
	sstr.len=strlen(";info=<");
	if (app2dynstr(&glb_sidentity, &sstr))
		return -9;

	sstr.s=glb_sservercerturl;
	sstr.len=strlen(glb_sservercerturl);
	if (app2dynstr(&glb_sidentity, &sstr))
		return -10;

	sstr.s=">\r\n";
	/* +1 : we need the trailing \0 character too */
	sstr.len=strlen(">\r\n") + 1;
	if (app2dynstr(&glb_sidentity, &sstr))
		return -11;


	//now append identity header to sip message
	if (append_hf(msg, getstr_dynstr(&glb_sidentity).s, HDR_IDENTITY_T))
		return -12;

	return 1;
}


// END AUTH FUNCTIONS
