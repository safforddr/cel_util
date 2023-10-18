/*
 * cel.h
 *
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * Defined Event Log Types for CEL-TLV
 *
 * TLV Encoding
 *	uint8_t t;	// type
 *	uint32_t l;	// length: Network Byte Order (Big-Endian!)
 *	uint8_t v[];	// value
 */

/* TCG CEL Top Level Field Types */
#define CEL_SEQ 			0
#define CEL_PCR 			1
#define CEL_NVINDEX			2
#define CEL_DIGEST 			3
#define CEL_CONTENT_MGT			4
#define CEL_CONTENT_PCCLIENT_STD	5
#define CEL_CONTENT_IMA_TEMPLATE 	7
#define CEL_CONTENT_IMA_TLV		8
#define CEL_CONTENT_SYSTEMD             9

/* IMA-TLV Specific Content Types */
#define IMA_TLV_CONTENT_PATH		0
#define IMA_TLV_CONTENT_DATAHASH	1
#define IMA_TLV_CONTENT_DATASIG		2
#define IMA_TLV_CONTENT_OWNER		3
#define IMA_TLV_CONTENT_GROUP		4
#define IMA_TLV_CONTENT_MODE		5
#define IMA_TLV_CONTENT_TIMESTAMP	6
#define IMA_TLV_CONTENT_LABEL		7

/* IMA_TEMPLATE Specific Content Types */
#define IMA_TEMPLATE_CONTENT_NAME 	0
#define IMA_TEMPLATE_CONTENT_VALUE	1

/* PCCLIENT_STD content types */
#define PCCLIENT_EVENT_TYPE 		0
#define PCCLIENT_EVENT_CONTENT		1

/* TCG Digest Types from TPM Specification */
#define TPM_ALG_SHA1           		4
#define TPM_ALG_SHA256			11
#define SHA1_HASH_LEN                   20
#define SHA256_HASH_LEN                 32
#define SHA384_HASH_LEN                 48

