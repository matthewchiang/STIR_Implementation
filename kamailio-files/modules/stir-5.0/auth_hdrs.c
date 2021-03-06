/*
 * $Id$
 *
 * Copyright (c) 2007 iptelorg GmbH
 *
 * This file is part of SIP-router, a free SIP server.
 *
 * SIP-router is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * SIP-router is distributed in the hope that it will be useful,
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
 * \brief SIP-router auth-identity :: Authentication headers
 * \ingroup auth-identity
 * Module: \ref auth-identity
 */

#include <errno.h>

#include "../../core/parser/parser_f.h"
#include "../../core/parser/parse_from.h"
#include "../../core/parser/parse_cseq.h"
#include "../../core/parser/parse_content.h"
#include "../../core/parser/parse_uri.h"
#include "../../core/parser/keys.h"
#include "../../core/parser/contact/parse_contact.h"

#include "../../modules/tm/ut.h"
#include "../../core/data_lump.h"
#include "../../core/msg_translator.h"
#include "auth_identity.h"


struct hdr_field glb_contact;
char *glb_siphdr=NULL;
char *glb_msgbody=NULL;

static char* construct_pass_pay(struct sip_msg *msg, time_t t);
static char* construct_pass_hdr(const struct sip_msg *msg, const char *x5u_URI);

static int tohdr_proc(str *sout, str *soutopt, struct sip_msg *msg);
static int in_contacthdr_proc(str *sout, str *soutopt, struct sip_msg *msg);
static int out_contacthdr_proc(str *sout, str *soutopt, struct sip_msg *msg);
static int in_msgbody_proc(str *sout, str *soutopt, struct sip_msg *msg);
static int out_msgbody_proc(str *sout, str *soutopt, struct sip_msg *msg);
static void free_out_contacthdr(void);
static void free_out_msgbody(void);


/* macros from the core parser */
#define LOWER_BYTE(b) ((b) | 0x20)
#define LOWER_DWORD(d) ((d) | 0x20202020)

#define READ(val) \
(*(val + 0) + (*(val + 1) << 8) + (*(val + 2) << 16) + (*(val + 3) << 24))

static char *auth_next_line(char *buf, char *buf_end);
static inline char* skip_ws(char* p, unsigned int size);
static char *auth_get_hf_name(char *begin, char *end, enum _hdr_types_t *type);
static int get_contact_body(char *buf, unsigned int len, str *sout);



/*
 *	Header parsing functions
 */

/* From */
int fromhdr_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	if ((!msg->from) && (parse_headers(msg, HDR_FROM_F, 0) == -1)) {
		LOG(L_ERR, "STIR module:fromhdr_proc: Error while parsing FROM header\n");
		return AUTH_ERROR;
	}
	if (!msg->from) {
		LOG(L_ERR, "STIR module:fromhdr_proc: FROM header field is not found\n");
		return AUTH_NOTFOUND;
	}
	/* we must call parse_from_header explicitly */
	if ((!(msg->from)->parsed) && (parse_from_header(msg) < 0)) {
		LOG(L_ERR, "STIR module:fromhdr_proc: Error while parsing FROM body\n");
		return AUTH_ERROR;
	}

	if (sout)
		*sout=get_from(msg)->uri;

	if (soutopt)
		*soutopt=get_from(msg)->tag_value;

	return AUTH_OK;
}

/* To */
static int tohdr_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	if (!msg->to && (parse_headers(msg, HDR_TO_F, 0) == -1)) {
		LOG(L_ERR, "STIR module:tohdr_proc: Error while parsing TO header\n");
		return AUTH_ERROR;
	}
	if (!msg->to) {
		LOG(L_ERR, "STIR module:tohdr_proc: TO header field is not found\n");
		return AUTH_NOTFOUND;
	}
	if (!msg->to->parsed) {
		LOG(L_ERR, "STIR module:tohdr_proc: TO is not parsed\n");
		return AUTH_ERROR;
	}

	if (sout)
		*sout=((struct to_body*)msg->to->parsed)->uri;

	return AUTH_OK;
}

/* Call-ID */
int callidhdr_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	if (!msg->callid && (parse_headers(msg, HDR_CALLID_F, 0) == -1)) {
		LOG(L_ERR, "STIR module:callidhdr_proc: error while parsing CALLID header\n");
		return AUTH_ERROR;
	}
	if (!msg->callid) {
		LOG(L_ERR, "STIR module:callidhdr_proc: CALLID header field is not found\n");
		return AUTH_NOTFOUND;
	}

	if (sout)
		*sout=msg->callid->body;

	return AUTH_OK;
}

/* CSeq */
int cseqhdr_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	if (!msg->cseq && (parse_headers(msg, HDR_CSEQ_F, 0) == -1)) {
		LOG(L_ERR, "STIR module:cseqhdr_proc: Error while parsing CSEQ header\n");
		return AUTH_ERROR;
	}
	if (!msg->cseq) {
		LOG(L_ERR, "STIR module:cseqhdr_proc: CSEQ header field is not found\n");
		return AUTH_NOTFOUND;
	}
	if (!msg->cseq->parsed) {
		LOG(L_ERR, "STIR module:cseqhdr_proc: CSEQ is not parsed\n");
		return AUTH_ERROR;
	}

	if (sout)
		*sout=get_cseq(msg)->number;
	if (soutopt)
		*soutopt=get_cseq(msg)->method;

	return AUTH_OK;
}

// Date
// Input: sip msg (if date exists in msg, is in msg->date)
// Output: sout = date->body ; return okay, error, or not found
int datehdr_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	if ((!msg->date) && (parse_headers(msg, HDR_DATE_F, 0) == -1)) {
		LOG(L_ERR, "STIR module:datehdr_proc: Error while parsing DATE header\n");
		return AUTH_ERROR;
	}
	if (!msg->date) {
		LOG(L_ERR, "STIR module:datehdr_proc: DATE header field is not found\n");
		return AUTH_NOTFOUND;
	}
	/* we must call parse_date_header explicitly */
	if ((!(msg->date)->parsed) && (parse_date_header(msg) < 0)) {
		LOG(L_ERR, "STIR module:datehdr_proc: Error while parsing DATE body\n");
		return AUTH_ERROR;
	}

	if (sout)
		*sout=msg->date->body;

	return AUTH_OK;
}


/* Contact header of the incoming SIP message */
static int in_contacthdr_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	if (!msg->contact && (parse_headers(msg, HDR_CONTACT_F, 0) == -1)) {
		LOG(L_ERR, "STIR module:in_contacthdr_proc: Error while parsing CONTACT header\n");
		return AUTH_ERROR;
	}
	if (!msg->contact) {
		return AUTH_NOTFOUND;
	}
	/* we must call parse_contact explicitly */
	if (!msg->contact->parsed && (parse_contact(msg->contact) < 0)) {
		LOG(L_ERR, "STIR module:in_contacthdr_proc: Error while parsing CONTACT body\n");
		return AUTH_ERROR;
	}

	if (sout)
		*sout=((contact_body_t*)msg->contact->parsed)->contacts->uri;

	return AUTH_OK;
}

/* Contact header of the outgoing SIP message */
static int out_contacthdr_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	unsigned int ulen;
	int ierror;
	struct dest_info dst;
	int ires;


#ifdef USE_DNS_FAILOVER
	/* get info about outbound socket */
	if ((uri2dst(NULL, &dst, msg, GET_NEXT_HOP(msg), PROTO_NONE) == 0)
#else
	if ((uri2dst(&dst, msg, GET_NEXT_HOP(msg), PROTO_NONE) == 0)
#endif
		|| (dst.send_sock == 0)) {
		LOG(L_ERR, "STIR module:out_contacthdr_proc: Can't determinate destination socket\n");
		return -1;
	}

	/* we save it to global variable because we'll process it later */
	glb_siphdr=build_only_headers(msg, 1, &ulen, &ierror, &dst);

	if (ierror)
		return -2;

	memset(&glb_contact, 0, sizeof(glb_contact));

	/* parse_contact() needs only the body element of "struct hdr_field" */
	ires=get_contact_body(glb_siphdr, ulen, &glb_contact.body);
	if (ires==AUTH_NOTFOUND) {
		pkg_free(glb_siphdr); glb_siphdr=NULL;
		return AUTH_NOTFOUND;
	}
	if (ires!=AUTH_OK) {
		pkg_free(glb_siphdr); glb_siphdr=NULL;
		return AUTH_ERROR;
	}

	if (parse_contact(&glb_contact) < 0) {
		pkg_free(glb_siphdr); glb_siphdr=NULL;
		return AUTH_ERROR;
	}

	if (sout)
		*sout=((contact_body_t*)glb_contact.parsed)->contacts->uri;

	return AUTH_OK;
}

/* Identity */
int identityhdr_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	if (!msg->identity && (parse_headers(msg, HDR_IDENTITY_F, 0) == -1)) {
		LOG(L_ERR, "STIR module:identityhdr_proc: Error while parsing IDENTITY header\n");
		return AUTH_ERROR;
	}
	if (!msg->identity) {
		return AUTH_NOTFOUND;
	}
	/* we must call parse_identity_header explicitly */
	if ((!(msg->identity)->parsed) && (parse_identity_header_stir(msg) < 0)) {
		LOG(L_ERR, "STIR module:identityhdr_proc: Error while parsing IDENTITY body\n");
		return AUTH_ERROR;
	}

	if (sout)
		*sout=get_identity_stir(msg)->hash;

	return AUTH_OK;
}

/* 
//Identity-info
int identityinfohdr_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	if (!msg->identity_info && (parse_headers(msg, HDR_IDENTITY_INFO_F, 0) == -1)) {
		LOG(L_ERR, "STIR module:identityinfohdr_proc: Error while parsing IDENTITY-INFO header\n");
		return AUTH_ERROR;
	}
	if (!msg->identity_info) {
		LOG(L_ERR, "STIR module:identityinfohdr_proc: IDENTITY-INFO header field is not found\n");
		return AUTH_NOTFOUND;
	}
	// we must call parse_identityinfo_header explicitly
	if ((!(msg->identity_info)->parsed) && (parse_identityinfo_header(msg) < 0)) {
		LOG(L_ERR, "STIR module:identityinfohdr_proc: Error while parsing IDENTITY-INFO body\n");
		return AUTH_ERROR;
	}

	if (sout)
		*sout=get_identityinfo(msg)->uri;
	if (soutopt)
		*soutopt=get_identityinfo(msg)->domain;

	return AUTH_OK;
}
*/


int getURLFromIdentity(str *sout, struct sip_msg *msg) {

	LOG(L_ERR, "Entering getURL()\n");

	if (!msg->identity && (parse_headers(msg, HDR_IDENTITY_F, 0) == -1)) {
		LOG(L_ERR, "STIR module:identityhdr_proc: Error while parsing IDENTITY header\n");
		return AUTH_ERROR;
	}
	if (!msg->identity) {
		return AUTH_NOTFOUND;
	}
	/* we must call parse_identity_header explicitly */
	if ((!(msg->identity)->parsed) && (parse_identity_header_stir(msg) < 0)) {
		LOG(L_ERR, "STIR module:identityhdr_proc: Error while parsing IDENTITY body\n");
		return AUTH_ERROR;
	}

	if (sout)
		*sout=get_identity_stir(msg)->url;

	return AUTH_OK;
}

/* body of the incoming SIP message */
static int in_msgbody_proc(str *sout, str *soutopt, struct sip_msg *msg)
{
	if (!sout)
		return AUTH_OK;

	sout->s = get_body(msg);
	if (!sout->s || sout->s[0] == 0) {
		sout->len = 0;
	} else {
		if (!msg->content_length) {
			LOG(L_ERR, "STIR module:route_msgbody_proc: no Content-Length header found!\n");
			return AUTH_ERROR;
		}
		sout->len = get_content_length(msg);
	}

	return AUTH_OK;
}

/* body of the outgoing SIP message */
static int out_msgbody_proc(str *sout, str *soutopt, struct sip_msg *msg)
{

	unsigned int len;
	int    err;
	struct dest_info dst;
	char scontentlen[AUTH_CONTENTLENGTH_LENGTH];


	if (!sout)
		return AUTH_OK;

#ifdef USE_DNS_FAILOVER
	/* get info about outbound socket */
	if ((uri2dst(NULL, &dst, msg, GET_NEXT_HOP(msg), PROTO_NONE) == 0)
#else
	if ((uri2dst(&dst, msg, GET_NEXT_HOP(msg), PROTO_NONE) == 0)
#endif
		|| (dst.send_sock == 0)) {
		LOG(L_ERR, "STIR module:rtend_msgbody_proc: Can't determinate destination socket\n");
		return -1;
	}

	/* we save it to global variable too to be able to free it later */
	sout->s = glb_msgbody = build_body(msg, &len, &err, &dst);
	if (err) {
		LOG(L_ERR, "STIR module:rtend_msgbody_proc: Can't build body (%d)\n", err);
		return -2;
	}

	sout->len = (int)len;

	/* authentication services MUST add a Content-Length header field to
	 * SIP requests if one is not already present
	 *
	 * content-length (if present) must be already parsed and if destination
	 * protocol is not UDP then core will append Content-Length
	 */
	if (!msg->content_length && dst.proto==PROTO_UDP) {
		snprintf(scontentlen, sizeof(scontentlen), "Content-Length: %d\r\n", len);
		scontentlen[sizeof(scontentlen)-1]=0;
		/* if HDR_CONTENTLENGTH_T's specified then the header won't be added! */
		if (append_hf(msg, scontentlen, HDR_OTHER_T)) {
			pkg_free(glb_msgbody);
			glb_msgbody=NULL;
			return -3;
		}
	}

	return AUTH_OK;
}

/* Contact header deinitializer of outgoing message */
static void free_out_contacthdr(void)
{
	void** h_parsed;

	h_parsed=&glb_contact.parsed; /*strict aliasing warnings workarround */
	if (glb_siphdr) {
		pkg_free(glb_siphdr);
		glb_siphdr=NULL;
	}

	if (glb_contact.parsed)
		free_contact((contact_body_t**)h_parsed);
}

/* body deinitializer of the outgoing message */
static void free_out_msgbody(void)
{
	if (glb_msgbody) {
		pkg_free(glb_msgbody);
		glb_msgbody=NULL;
	}
}

/* Digest-string assembler function (RFC 4474 [9] */
// Output: sout has complete SIP headers
int digeststr_asm(dynstr *sout, struct sip_msg *msg, str *sdate, int iflags)
{
	/* incoming SIP message parser describer */
	dgst_part incoming_sip_digest_desc[] = {
		{ DS_FROM, fromhdr_proc, NULL, DS_REQUIRED },
		{ DS_TO, tohdr_proc, NULL, DS_REQUIRED },
		{ DS_CALLID, callidhdr_proc, NULL, DS_REQUIRED },
		{ DS_CSEQ, cseqhdr_proc, NULL, DS_REQUIRED },
		{ DS_DATE, datehdr_proc, NULL, DS_NOTREQUIRED },
		{ DS_CONTACT, in_contacthdr_proc, NULL, DS_NOTREQUIRED },
		{ DS_BODY, in_msgbody_proc, NULL, DS_NOTREQUIRED },
		{ 0, NULL, NULL, 0 }
	};
	/* outgoing SIP message parser describer */
	dgst_part outgoing_sip_digest_desc[] = {
		{ DS_FROM, fromhdr_proc, NULL, DS_REQUIRED },
		{ DS_TO, tohdr_proc, NULL, DS_REQUIRED },
		{ DS_CALLID, callidhdr_proc, NULL, DS_REQUIRED },
		{ DS_CSEQ, cseqhdr_proc, NULL, DS_REQUIRED },
		{ DS_DATE, datehdr_proc, NULL, DS_NOTREQUIRED },
		{ DS_CONTACT, out_contacthdr_proc, free_out_contacthdr, DS_NOTREQUIRED },
		{ DS_BODY, out_msgbody_proc, free_out_msgbody, DS_NOTREQUIRED },
		{ 0, NULL, NULL, 0 }
	};
	//dgst_part = { itype, *function to parse, *destructor function, iflag }
	dgst_part *pactpart;
	dgst_part *sip_digest_desc; //fields for this message
	str sact, sactopt;
	int i1; //loop iterator
	int iRes;


	// AUTH_INCOMING_BODY xor AUTH_OUTGOING BODY : one of two must be set
	// sip_digest_desc = incoming or outcoming struct above
	if ((iflags & AUTH_INCOMING_BODY) ^ (iflags & AUTH_OUTGOING_BODY)) {
		(iflags & AUTH_INCOMING_BODY) ?
			(sip_digest_desc = incoming_sip_digest_desc) :
			(sip_digest_desc = outgoing_sip_digest_desc);
	} 
	else return -1;

	resetstr_dynstr(sout);

	for (pactpart=&sip_digest_desc[0],i1=0; pactpart[i1].itype; i1++) {
		iRes=pactpart[i1].pfunc(&sact, &sactopt, msg);

		// there was an error or the required header is missing
		if (iRes==AUTH_ERROR
				|| (iRes==AUTH_NOTFOUND && (pactpart[i1].iflag & DS_REQUIRED)))
			return -1;

		switch (pactpart[i1].itype) {
			/* Cseq handle (we need SP instead of LWS (RFC4474 [9])) */
			case DS_CSEQ:
				//sact = 32 bit int
				//sactopt = SIP method
				if (app2dynstr(sout,&sact))
					return -1;
				if (app2dynchr(sout,' '))
					return -2;
				if (app2dynstr(sout,&sactopt))
					return -3;
				break;
			case DS_DATE:
				//if no date found, add date from argument (current time)
				if (iRes==AUTH_NOTFOUND) {
					if (iflags & AUTH_ADD_DATE) {
						if (app2dynstr(sout,sdate))
							return -8;
					} else {
						/* Date header must exist */
						LOG(L_ERR, "STIR module:digeststr_asm: DATE header is not found\n");
						return -9;
					}
				}
			default:
				if (iRes==AUTH_NOTFOUND) //non-essential header missing: ignore
					break;
				if (app2dynstr(sout,&sact)) //append header to sout
					return -10;
		} //end switch

		// if there is destructor function available then we call it
		if (pactpart[i1].pfreefunc)
			pactpart[i1].pfreefunc();

		// append separator '|' except for body field
		if (pactpart[i1+1].itype) {
			if (app2dynchr(sout,'|'))
				return -11;
		}
	} //end for loop

	return 0;
}


//ASSEMBLE STIR PASSPORT**********************************************************************************************

	//.*** dest: {uri : sip:... }
	//.*** orig: {tn: 122121....}

static char* construct_pass_hdr(const struct sip_msg *msg, const char *x5u_URI) {
	char *ret = malloc(256);

	strcat(strcpy(ret, "{"), "\"alg\":\"ES256\",");
	strcat(ret, "\"typ\":\"passport\",");
	strcat(strcat(strcat(ret, "\"x5u\":\""), x5u_URI), "\"}");

	return ret;
};


static char* construct_pass_pay(struct sip_msg *msg, time_t msg_time) {

	char *ret = (char*)malloc(256);
	str sact, sactopt;
	int iRes;
	char *temp_to_add_ppt = (char*)malloc(256);

	//check if FROM (ORIG) is URI or tn
	//if contains @, URI ; otherwise tn

	if (msg == NULL) {
		LOG(L_ERR, "msg is empty\n");
		return NULL;
	}

	strcpy(ret, "{\"dest\":{\"uri\":[\"");

	if (fromhdr_proc(&sact, &sactopt, msg) != AUTH_OK) {
		LOG(L_ERR, "STIR: construct_pass_pay: error in getting from field\n");
		return NULL;
	}

	memcpy(temp_to_add_ppt, sact.s, sact.len);

	strcat(strcat(ret, temp_to_add_ppt), "\"]},");
	strcat(ret, "\"iat\":");


	iRes = datehdr_proc(&sact, &sactopt, msg);
	if (iRes == AUTH_OK) {
		LOG(L_ERR, "okay..\n");
		LOG(L_ERR, "printing date: %s\n", sact.s);
		sact.s[sact.len] = 0;
		strcat(ret, sact.s); //time of call
	}
	else if (iRes == AUTH_NOTFOUND) {
		char str_date[11];
		sprintf(str_date, "%i", (int)msg_time);
		strcat(ret, str_date); //no date: current time
	}
	else {
		LOG(L_ERR, "STIR: construct_pass_pay: date not found!\n");
		free(ret);
		return NULL;
	}


	strcat(ret, ",\"orig\":{\"uri\":[\"");

	if (tohdr_proc(&sact, &sactopt, msg) != AUTH_OK) {
		LOG(L_ERR, "STIR: construct_pass_pay: error in getting to field\n");
		return NULL;
	}

	memcpy(temp_to_add_ppt, sact.s, sact.len);

	strcat(strcat(ret, temp_to_add_ppt), "\"]}}");

	//can potentially replace dest with gdrp for group calls

	return ret;

};


//rfc 7515 part 5.1
// Output: sout has string to hash + sign
int assemble_passport(dynstr *sout, struct sip_msg *msg, time_t tdate, char *x5u_URI, EC_KEY *eckey) {

	char *hdr = construct_pass_hdr(msg, x5u_URI);
	char *pay = construct_pass_pay(msg, tdate);

	//debug: print passport values
	//LOG(L_ERR, "val of hdr: %s\n", hdr);
	//LOG(L_ERR, "val of pay: %s\n", pay);
	
	char* outstr_pay = (char*)malloc(256);
	int outlen_pay = 0;
	char* outstr_hdr = (char*)malloc(256);
	int outlen_hdr = 0;

	//base64(hdr) and base64(pay)
	base64encode(pay, strlen(pay), outstr_pay, &outlen_pay);
	base64encode(hdr, strlen(hdr), outstr_hdr, &outlen_hdr);

	//create [hdr . pay]
	char* str_to_sign = (char*)malloc(outlen_hdr+outlen_pay+2);
	strcat(strcat(strcpy(str_to_sign, outstr_hdr), "."), outstr_pay);

	//hash [hdr . pay]
	char* hashed_str = (char*)malloc(33);
	SHA256((unsigned char*)str_to_sign, strlen(str_to_sign), (unsigned char*)hashed_str);

	//sign (digest)
	ECDSA_SIG *sig = (ECDSA_SIG *)malloc(128);
	sig = ECDSA_do_sign((unsigned char*)hashed_str, 32, eckey);
	
	//extract r and s as octects
	char* to_r = (char*)malloc(32);
	char* to_s = (char*)malloc(32);
	BN_bn2bin(sig->r, (uint8_t*)to_r);
	BN_bn2bin(sig->s, (uint8_t*)to_s);

	// r_and_s = r || s
	char* r_and_s = (char*)malloc(64);
	strcat(strcpy(r_and_s, to_r), to_s);
	int r_and_s_len = strlen(r_and_s);

	//base64(jws)
	char* outstr_jws = (char*)malloc(256);
	int outlen_jws = 0;

	base64encode(r_and_s, r_and_s_len, outstr_jws, &outlen_jws);

	//prepare sout for return
	resetstr_dynstr(sout);

	if (tdate == 0) {
		//date exists: just return outstr_jws
		str add;
		add.s = outstr_jws;
		add.len = outlen_jws;
		if (app2dynstr(sout,&add)) {
			LOG(L_ERR, "STIR: assemble_passport: error -1\n");
			return -1;
		}
	}

	else {
		//no date in msg: return whole passport as hdr . pay . jws
		str add;
		add.s = outstr_hdr;
		add.len = outlen_hdr;
		if (app2dynstr(sout,&add)) {
			LOG(L_ERR, "STIR: assemble_passport: error -2\n");
			return -2;
		}
		if (app2dynchr(sout,'.')) {
			LOG(L_ERR, "STIR: assemble_passport: error -3\n");
			return -3;
		}
		add.s = outstr_pay;
		add.len = outlen_pay;
		if (app2dynstr(sout,&add)) {
			LOG(L_ERR, "STIR: assemble_passport: error -4\n");
			return -4;
		}
		if (app2dynchr(sout,'.')) {
			LOG(L_ERR, "STIR: assemble_passport: error -5\n");
			return -5;
		}
		add.s = outstr_jws;
		add.len = outlen_jws;
		if (app2dynstr(sout,&add)) {
			LOG(L_ERR, "STIR: assemble_passport: error -6\n");
			return -6;
		}
	}


	return 0;	
}



// END ASSEMBLE PASSPORT*********************************************************************


/* copypasted and ripped from ser/modules/textops/textops.c) */
// appends new hdr to sip msg
int append_hf(struct sip_msg* msg, char *str1, enum _hdr_types_t type)
{
	struct lump* anchor;
	char* s;
	int len;

	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LOG(L_ERR, "STIR module:append_hf: Error while parsing message\n");
		return -1;
	}

	anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0, type);
	if (anchor == 0) {
		LOG(L_ERR, "STIR module:append_hf: Can't get anchor\n");
		return -1;
	}

	len=strlen(str1);

	s = (char*)pkg_malloc(len);
	if (!s) {
		LOG(L_ERR, "STIR module:append_hf: No memory left\n");
		return -1;
	}

	memcpy(s, str1, len);

	if (insert_new_lump_before(anchor, s, len, type) == 0) {
		LOG(L_ERR, "STIR module:append_hf: Can't insert lump\n");
		pkg_free(s);
		return -1;
	}
	return 0;
}


// get the current system date and appends it to the message
// return current system date in tout and sdate arguments
int append_date(str *sdate, int idatesize, time_t *tout, struct sip_msg *msg)
{
	char date_hf[AUTH_TIME_LENGTH];
	char date_str[AUTH_TIME_LENGTH];
	time_t tdate_now;
	struct tm *bd_time;
	size_t ilen;
	int istrlen;


	if ((tdate_now=time(0)) < 0) {
		LOG(L_ERR, "STIR module:append_date: time error %s\n", strerror(errno));
		return -1;
	}
	if (!(bd_time=gmtime(&tdate_now))) {
		LOG(L_ERR, "STIR module:append_date: gmtime error\n");
		return -2;
	}

	ilen=strftime(date_str, sizeof(date_str), AUTH_TIME_FORMAT, bd_time);
	if (ilen >= sizeof(date_hf) - strlen("Date: \r\n.") || ilen==0) {
		LOG(L_ERR, "STIR module:append_date: unexpected time length\n");
		return -3;
	}

	/* we append the date header to the message too */
	istrlen=strlen("Date: ");
	memcpy(date_hf,"Date: ",istrlen);
	memcpy(date_hf+istrlen,date_str,ilen);
	istrlen+=ilen;
	date_hf[istrlen]='\r'; date_hf[istrlen+1]='\n'; date_hf[istrlen+2]=0;
	if (append_hf(msg, date_hf, HDR_DATE_T))
		return -4;

	if (sdate && idatesize >= ilen) {
		memcpy(sdate->s, date_str, ilen);
		sdate->len=ilen;
	} else {
		return -5;
	}

	if (tout)
		*tout=tdate_now;

	return 0;
}

/*
 *
 *	"Contact" header parser part
 *
 */


/* returns a pointer to the next line */
static char *auth_next_line(char *buf, char *buf_end)
{
	char	*c;

	c = buf;
	do {
		while ((c < buf_end) && (*c != '\n')) c++;
		if (c < buf_end) c++;
		if ((c < buf_end) && (*c == '\r')) c++;

	} while ((c < buf_end) && ((*c == ' ') || (*c == '\t')));	/* next line begins with whitespace line folding */

	return c;
}

/*
 * Skip all white-chars and return position of the first
 * non-white char
 */
static inline char* skip_ws(char* p, unsigned int size)
{
	char* end;

	end = p + size;
	for(; p < end; p++) {
		if ((*p != ' ') && (*p != '\t')) return p;
	}
	return p;
}

/* looks for "Contact" header */
static char *auth_get_hf_name(char *begin, char *end, enum _hdr_types_t *type)
{
	char *p;
	unsigned int val;


	if (end - begin < 4) {
		*type = HDR_ERROR_T;
		return begin;
	}

	p = begin;
	val = LOWER_DWORD(READ(p));

	switch(val) {
		case _cont_:	/* Content-Length */
			p+=4;
			switch (LOWER_DWORD(READ(p))) {
			case _act1_:
				*type = HDR_CONTACT_T;
				return (p + 4);
			case _act2_:
				*type = HDR_CONTACT_T;
				p += 4;
				goto dc_end;
			}
		default:
			/* compact headers */
			switch(LOWER_BYTE(*p)) {
			case 'm':
				switch(*(p + 1)) {
				case ' ':
					*type = HDR_CONTACT_T;
					p += 2;
					goto dc_end;
				case ':':
					*type = HDR_CONTACT_T;
					return (p + 2);
				}
			default:
				*type = HDR_OTHER_T;
				break;
			}
	}

dc_end:
	p = skip_ws(p, end - p);
	if (*p != ':') {
		goto other;
	} else {
		return (p + 1);
	}

	/* Unknown header type */
other:
	p = q_memchr(p, ':', end - p);
	if (!p) {        /* No double colon found, error.. */
		*type = HDR_ERROR_T;
		return 0;
	} else {
		*type = HDR_OTHER_T;
		return (p + 1);
	}

	return p;
}

/* parses buffer that contains a SIP message header, looks for "Contact"
 * header field and returns the value of that */
static int get_contact_body(char *buf, unsigned int len, str *sout)
{
	char *end, *s, *tmp, *match;
	enum _hdr_types_t hf_type;


	end = buf + len;
	s = buf;

	memset(sout, 0, sizeof(*sout));

	while (s < end) {
		if ((*s == '\n') || (*s == '\r')) {
			/* end of SIP msg */
			hf_type = HDR_EOH_T;
		} else {
			/* parse HF name */
			if (!(s = auth_get_hf_name(s, end, &hf_type)))
				return AUTH_ERROR;
		}

		switch(hf_type) {
			case HDR_CONTACT_T:
				tmp=eat_lws_end(s, end);
				if (tmp>=end) {
					LOG(L_ERR, "STIR module:get_contact_body: get_hdr_field: HF empty\n");
					return AUTH_ERROR;
				}
				sout->s=tmp;
				/* find lf */
				do{
					match=q_memchr(tmp, '\n', end-tmp);
					if (match){
						match++;
					}else {
						LOG(L_ERR, "STIR module:get_contact_body: bad msg body\n");
						return AUTH_ERROR;
					}
					tmp=match;
				} while( match<end &&( (*match==' ')||(*match=='\t') ) );
				tmp=match;
				sout->len=match-sout->s;
				trim_r(*sout);
				return AUTH_OK;
				break;
			case HDR_ERROR_T:
				return AUTH_ERROR;
			default:
				s = auth_next_line(s, end);
		}
	}

	return AUTH_NOTFOUND;
}
