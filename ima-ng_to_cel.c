/*
 * ima-ng (binary) to cel
 *
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * Reads pcclient log from stdin, and puts CEL encapsulated events to stdout
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <tss2/tss2_tpm2_types.h>
#include "cel.h"

/* max values for this parser */
#define MAX_EVENT_SIZE 2048
#define MAX_DIGEST_SIZE 48
#define MAX_NUM_DIGESTS 3

/* in an event2, collect all the digests for CEL encapsulation */
struct digest {
	uint16_t algid;
	uint32_t len;
	uint8_t data[MAX_DIGEST_SIZE];
} digests[MAX_NUM_DIGESTS];

/* Only dealing with PCR10 sequence */
uint32_t seq = 0;

void tlv_put(uint8_t t, uint32_t l, unsigned char v[])
{
	uint32_t nl;
	ssize_t ret;
	
	nl = htonl(l);
	ret = write(1, &t, 1);
	ret = write(1, &nl, 4);
	ret = write(1, v, l);
	(void)ret;
}

void raw_put(uint8_t *v, int l)
{
	ssize_t ret;
	ret = write(1, v, l);
	(void)ret;
}

bool read_uint32(uint32_t *t) {
	uint32_t tmp;
	ssize_t l;
	l = read(0, &tmp, 4);
	if (l != 4)
	        return false;
	*t = tmp;
	return true;
}

bool read_imang(void) {
	uint32_t pcr, tmp;
	uint8_t digest[SHA1_HASH_LEN], t;
	uint32_t template_name_len;
	uint8_t *template_name;
	uint32_t template_data_len;
	uint8_t *template_data;

	if (!read_uint32(&pcr))
	        return false;
	if (read(0, digest, SHA1_HASH_LEN) != SHA1_HASH_LEN)
	        return false;

	if (!read_uint32(&template_name_len))
	        return false;
	if (!(template_name = malloc(template_name_len)))
	        return false;
	if (read(0, template_name, template_name_len) != template_name_len)
	        return false;

	if (!read_uint32(&template_data_len))
	        return false;
	if (!(template_data = malloc(template_data_len)))
	        return false;
	if (read(0, template_data, template_data_len) != template_data_len)
	        return false;

	/* CEL_SEQ */
	tmp = htonl(seq++);
	tlv_put(CEL_SEQ, 4, (unsigned char *) &tmp);
	
	/* CEL_PCR */
	tmp = htonl(pcr);
	tlv_put(CEL_PCR, 4, (unsigned char *) &tmp);
	
	/* CEL_DIGEST */
	t = CEL_DIGEST;
	raw_put(&t, 1);
	tmp = htonl(SHA1_HASH_LEN + 5);
	raw_put((unsigned char *)&tmp, 4);
	tlv_put(TPM2_ALG_SHA1, SHA1_HASH_LEN, (unsigned char *)digest);

	/* CEL_CONTENT */
	t = CEL_CONTENT_IMA_TEMPLATE;
	raw_put(&t, 1);
	tmp = htonl(template_name_len + template_data_len + 5 + 5);
	raw_put((unsigned char *) &tmp, 4);
	
	/* IMA_TEMPLATE_CONTENT_NAME TLV ("ima-ng")*/
	tlv_put(IMA_TEMPLATE_CONTENT_NAME, template_name_len,
	        (unsigned char *)template_name);
	
	/* IMA_TEMPLATE_CONTENT_VALUE (filehash, filename)*/
	tlv_put(IMA_TEMPLATE_CONTENT_VALUE, template_data_len,
	        (unsigned char *)template_data);

	return true;
}

/* Read imang events and translate to CEL. */
int main(int argc, char *argv[]) {
	while (read_imang())
	        ;
}
