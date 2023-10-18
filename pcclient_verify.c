/*
 * PCCLIENT support functions for cel_verify
 *
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <asm/byteorder.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include "cel.h"
#include "cel_verify.h"
#include "pcclient.h"
#include "pcclient_verify.h"

/*
 * Handle PCCLIENT_TLV events
 * The content has two TLV's:
 *	EVENT_TYPE (4 bytes) and
 *	EVENT_CONTENT (variable)
 * The EVENT_CONTENT may be an unauthenticated hint about the hashed binary,
 * or it may be related to the buffer that is hashed.
 */

static void display_pcclient(struct tlv *tlv)
{
	uint32_t ptype;
	
	if (tlv->t == PCCLIENT_EVENT_TYPE) {
		ptype = ntohl(*(uint32_t *)tlv->v);
		if (ptype < 20)
			printf("%s ", pcclient_type_low[ptype]);
		else {
			ptype &= 0x7fffffff;
			if (ptype < 10)
				printf("%s ", pcclient_type_efi[ptype]);
			else if (ptype == 16)
				printf("EV_EFI_HCRTM_EVENT ");
			else if (ptype == 0xe0)
				printf("EV_EFI_VARIABLE_AUTHORITY ");
			else
				printf("BADTYPE %d ", ptype);
		}		
	} else if (tlv->t == PCCLIENT_EVENT_CONTENT) {
	        if (verbose) {
		        printf("\nCONTENT\n");
		        hexdump(tlv->v, tlv->l);
		        printf("\n");
		        ascii_dump(tlv->v, tlv->l);
		        printf("\n");
		}
	} else {
		printf("Unknown content type %02d %02d ",tlv->t, tlv->l);
		hexdump(tlv->v, tlv->l);
	}
}
		
void display_pcclient_content(struct tlv *tlv)
{
	struct tlv *tmp;
	int pos;

	printf("CEL_CONTENT_PCCLIENT ");
	/* Walk through the PCCLIENT TYPE and CONTENT nested tlv's. */
	for (pos=0; pos + 5 < tlv->l; ) {
		tmp = (struct tlv *)((unsigned char *)tlv + pos + 5);		
		display_pcclient(tmp);
		pos += tmp->l + 5;
	}
}

void fix_pcclient_content(struct tlv *tlv) {
	struct tlv *tmp;
	int pos;

	/* fix lengths in nested pcclient content tlvs */
	for (pos=0; pos + 5 < tlv->l; ) {
		tmp = (struct tlv *)((unsigned char *)tlv + pos + 5);
		tmp->l = ntohl(tmp->l);			
		pos += tmp->l + 5;
	}
}

/*
 * verified_digest is 0 or 1
 * verified_rim is -1 or index of matching line in rims
 */
void verify_pcclient_content(struct record *r) {
	struct tlv *tmp, *tlv;
	int i, pos;

	tlv = r->content;
	for (pos=0; pos + 5 < tlv->l; ) {
		tmp = (struct tlv *)((unsigned char *)tlv + pos + 5);
		if (tmp->t == PCCLIENT_EVENT_CONTENT) {
		        if (verify_sha256(r->sha256, tmp->v, tmp->l) == 0)
		                r->verified_digests = 1;
		        else if ((i = verify_by_rim(r->sha256)) >= 0)
		                r-> verified_rim = i;
		}
		pos += tmp->l + 5;
	}
}

