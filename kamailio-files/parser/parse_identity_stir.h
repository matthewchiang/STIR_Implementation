/*
 * Copyright (c) 2007 iptelorg GmbH
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*! \file
 * \brief Parser :: Parse Identity header field
 *
 * \ingroup parser
 */


#ifndef PARSE_IDENTITY_STIR
#define PARSE_IDENTITY_STIR

#include "../str.h"
#include "msg_parser.h"

struct identity_body_stir{
	int error;  		/*!< Error code */
	int ballocated;  	/*!< Does hash point to an allocated area */
	str hash;
	str url;
};


/*! \brief casting macro for accessing IDENTITY body */
#define get_identity_stir(p_msg) ((struct identity_body_stir*)(p_msg)->identity->parsed)


/*! \brief
 * Parse Identity header field
 */
void parse_identity_stir(char *buf, char *end, struct identity_body_stir *ib);

/*! \brief
 * Parse Identity header field
 */
int parse_identity_header_stir(struct sip_msg *msg);


/*! \brief
 * Free all associated memory
 */
void free_identity_stir(struct identity_body_stir *ib);


#endif
