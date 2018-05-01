/*$Id$
 *
 * Example ser module, it will just print its string parameter to stdout
 *
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
/*
 * History:
 * --------
 *  2003-03-10  module export interface updated to the new format (andrei)
 *  2003-03-11  flags export parameter added (janakj)
 *  2006-01-07  str export parameter added, overloading test (tma)
 */




#include "../../core/sr_module.h"
#include "../../core/route_struct.h"
#include "../../core/str.h"
#include "../../core/parser/sdp/sdp.h"
#include <stdio.h>
#include <time.h>

MODULE_VERSION

static void print_sdp_info(struct sip_msg *msg);
static int add_PSTN_to_SDP(struct sip_msg *msg);
static int check_SDP_for_PSTN(struct sip_msg *msg);
static int add_value_to_SDP(struct sip_msg *msg);
static int mod_init(void);

/* the parameters are not used, they are only meant as an example*/
char* string_param = 0;
int int_param = 0;
str str_param = STR_STATIC_INIT("");

// exported functions to be called in /usr/local/etc/kamailio/kamailio.cfg
static cmd_export_t cmds[]={
	{"print_sdp_info", print_sdp_info, 0, 0, REQUEST_ROUTE},
	{"add_PSTN_to_SDP", add_PSTN_to_SDP, 0, 0, REQUEST_ROUTE},
	{"check_SDP_for_PSTN", check_SDP_for_PSTN, 0, 0, REQUEST_ROUTE},
	{"add_value_to_SDP", add_value_to_SDP, 0, 0, REQUEST_ROUTE},
	{0, 0, 0, 0, 0}
};

static param_export_t params[]={
	// {"string_param", PARAM_STRING, &string_param},
	// {"str_param",    PARAM_STR, &str_param},
	// {"int_param",    PARAM_INT, &int_param},
	{0,0,0}
};

struct module_exports exports = {
	"pstn_sip_secure",
	cmds,
	0,        /* RPC methods */
	params,

	mod_init, /* module initialization function */
	0,        /* response function*/
	0,        /* destroy function */
	0,        /* oncancel function */
	0         /* per-child init function */
};


static int mod_init(void)
{
	LM_ERR("in mod_init for pstn_sip_secure"); //prints as error to syslog: /var/log/syslog.
	//WARN("this prints a warning to syslog\n");

	// using parameters...
	//DBG("print: string_param = '%s'\n", string_param);
	//DBG("print: str_param = '%.*s'\n", str_param.len, str_param.s);
	//DBG("print: int_param = %d\n", int_param);
	LM_ERR("LM_ERR test");
	
	// print_sdp_info(NULL);

	return 0;
}


static void print_sdp_info(struct sip_msg *msg) {

	// sdp_session_cell_t *session;

	if (msg == NULL) {
		LM_ERR("print_sdp_info(): null msg\n");
		return;
	}

	/* Check for SDP. */
	if (0 == parse_sdp(msg)) {
		LM_ERR("print_sdp_info(): SDP found\n");
		/* Let's print the content of SDP via a DBG log.
		 * Check openser logs to see the output.
		 */

		/* initializing pointer to the first session
		 * and start iterating through sessions.
		 */	
		char* body;
		body = get_body(msg);
		LM_ERR("print_sdp_info(): here is body: %s\n", body);

		
		// session = msg->sdp->sessions;
		// while (session) {
		//     print_sdp_session(session);
		//     session = session->next;
		// }
	}

}

// 1 added successfully; otherwise error
static int add_PSTN_to_SDP(struct sip_msg *msg) {

	if (msg == NULL) {
		LM_ERR("add_PSTN_to_SDP(): null msg\n");
		return -1;
	}

	/* Check for SDP. */
	if (0 == parse_sdp(msg)) {
		// LM_ERR("add_PSTN_to_SDP(): SDP found\n");

		char* body;
		body = get_body(msg);
		LM_ERR("add_PSTN_to_SDP(): here is body(before): %s\n", body);

		char* lastAttrib;
		lastAttrib = strstr(body, "a=sendrecv");
		if (!lastAttrib) {
			LM_ERR("add_PSTN_to_SDP(): ERROR: no lastAttrib\n");
			// return -2;
		}
		LM_ERR("add_PSTN_to_SDP(): here is last attrib: %s\n", lastAttrib);
		strcpy(lastAttrib, "a=pstn-mc");
		// strcpy(body, "a=lkwejrlkew1234321\r\n");
		// strcat(body, "a=lkwejrlkew1234321\n");
		LM_ERR("add_PSTN_to_SDP(): here is body(after): %s\n", body);
		return 1;
	}
	return -2;
}

// return 1 if PSTN in SDP; 0 if not; negative if error
static int check_SDP_for_PSTN(struct sip_msg *msg) {

	if (msg == NULL) {
		LM_ERR("check_SDP_for_PSTN(): null msg\n");
		return -1;
	}

	/* Check for SDP. */
	if (0 == parse_sdp(msg)) {
		// LM_ERR("check_SDP_for_PSTN(): SDP found\n");

		char* body;
		body = get_body(msg);
		LM_ERR("check_SDP_for_PSTN(): here is body: %s\n", body);

		char* lastAttrib;
		lastAttrib = strstr(body, "a=pstn-mc");
		if (!lastAttrib) { //not pstn
			LM_ERR("check_SDP_for_PSTN(): no pstn\n");
			return 0;
		}
		else {
			LM_ERR("check_SDP_for_PSTN(): has pstn\n");
			return 1;
		}
	}
	return -2;
}


// adds random number
// note: NOT cryptographically secure
static int add_value_to_SDP(struct sip_msg *msg) {

	if (msg == NULL) {
		LM_ERR("add_value_to_SDP(): null msg\n");
		return -1;
	}

	// Check for SDP.
	if (0 == parse_sdp(msg)) {
		// LM_ERR("add_value_to_SDP(): SDP found\n");
		
		srand(time(NULL));
		int r = rand();
		char str_r[2] = {'9', '\0'};
		char* body;
		body = get_body(msg);
		// LM_ERR("add_value_to_SDP(): here is body: %s\n", body);

		char* lastAttrib;
		lastAttrib = strstr(body, "a=pstn-mc");
		strcpy(lastAttrib, str_r);
		LM_ERR("add_value_to_SDP(): here is last attrib: %s\n", lastAttrib);
		return 1;
	}
	return -2;

}