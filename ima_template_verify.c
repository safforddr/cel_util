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
#include "pcclient_verify.h"

/*
 * Handle ima-ng events
 */

static void display_ima_template(struct tlv *tlv) {
	if (tlv->t == IMA_TEMPLATE_CONTENT_NAME) {
	        char name[256];
	        memset(name, 0, sizeof(name));
	        strncpy(name, (char *)tlv->v, tlv->l);
	        printf("Template name %s ",name);
	} else if (tlv->t == IMA_TEMPLATE_CONTENT_VALUE) {
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
		
void display_ima_template_content(struct tlv *tlv) {

	struct tlv *tmp;
	int pos;

	printf("CEL_CONTENT_IMA_TEMPLATE ");
	/* Walk through the IMA_TEMPLATE TYPE and CONTENT nested tlv's. */
	for (pos=0; pos + 5 < tlv->l; ) {
		tmp = (struct tlv *)((unsigned char *)tlv + pos + 5);		
		display_ima_template(tmp);
		pos += tmp->l + 5;
	}
}

void fix_ima_template_content(struct tlv *tlv) {
	struct tlv *tmp;
	int pos;

	/* fix lengths in nested ima template content tlvs */
	for (pos=0; pos + 5 < tlv->l; ) {
		tmp = (struct tlv *)((unsigned char *)tlv + pos + 5);
		tmp->l = ntohl(tmp->l);			
		pos += tmp->l + 5;
	}
}

/*
 * IMA Template has a fixed sha1 digest. For sha256 banks, this
 *     we have to calculate sha256(original template data field)
 */
void fix_ima_template_sha1(struct record *r) {

	struct tlv *tmp, *tlv;
	int pos;

	tlv = r->content;
	for (pos=0; pos + 5 < tlv->l; ) {
		tmp = (struct tlv *)((unsigned char *)tlv + pos + 5);
		if (tmp->t == IMA_TEMPLATE_CONTENT_VALUE) {
	                calculate_sha256(r->sha256, tmp->v, tmp->l);
	                r->have_sha256 = 1;
	        }
		pos += tmp->l + 5;
	}
}

/*
 * verified_digest is 0 or 1
 * verified_rim is -1 or index of matching line in rims
 */
void verify_ima_template_content(struct record *r) {
	struct tlv *tmp, *tlv;
	int i, pos;

	tlv = r->content;
	for (pos=0; pos + 5 < tlv->l; ) {
		tmp = (struct tlv *)((unsigned char *)tlv + pos + 5);
		if (tmp->t == IMA_TEMPLATE_CONTENT_VALUE) {
		        if (verify_sha256(r->sha256, tmp->v, tmp->l) == 0)
		                r->verified_digests = 1;
		        else if ((i = verify_by_rim(r->sha256)) >= 0)
		                r-> verified_rim = i;
		}
		pos += tmp->l + 5;
	}
}

