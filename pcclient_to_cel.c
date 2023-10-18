/*
 * pcclient_to_cel
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

/* sequence numbers are per PCR */
uint32_t seqs[TPM2_MAX_PCRS];

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
	*t = tmp;   /* assuming we are pcclient native...*/
	return true;
}

bool read_digest(int i) {
	if (read(0, &digests[i].algid, 2) != 2)
	        return false;
	if (digests[i].algid == TPM2_ALG_SHA1)
	        digests[i].len = SHA1_HASH_LEN;
	else if (digests[i].algid == TPM2_ALG_SHA256)
	        digests[i].len = SHA256_HASH_LEN;
	else if (digests[i].algid == TPM2_ALG_SHA384)
	        digests[i].len = SHA384_HASH_LEN;
	else
	        return false;
	if (read(0, digests[i].data, digests[i].len) != digests[i].len)
	        return false;
	return true;
}

bool read_event2() {
	uint32_t pcr;
	uint32_t event_type;
	uint8_t *event_data;
	uint32_t event_size;
	uint32_t digest_count;
	int i, len = 0;
	uint8_t t;
	uint32_t tmp;

	if (!read_uint32(&pcr))
	        return false;	
	if (!read_uint32(&event_type))
	        return false;
	if (!read_uint32(&digest_count))
	        return false;
	for (i=0;i<digest_count;i++) {
	        if(!read_digest(i))
	                return false;
	        len += digests[i].len + 5;
	}
	if (!read_uint32(&event_size))
	        return false;
	if (!(event_data = malloc(event_size)))
	        return false;
	if (read(0, event_data, event_size) != event_size)
	        return false;

	/* CEL_SEQ */
	tmp = htonl(seqs[pcr]++);
	tlv_put(CEL_SEQ, 4, (unsigned char *) &tmp);
	
	/* CEL_PCR */
	tmp = htonl(pcr);
	tlv_put(CEL_PCR, 4, (unsigned char *) &tmp);
	
	t = CEL_DIGEST;
	raw_put(&t, 1);
	tmp = htonl(len);
	raw_put((unsigned char *)&tmp, 4);   	
	for (i=0;i<digest_count;i++){
		t = digests[i].algid;
	        tlv_put(t, digests[i].len, (unsigned char *)digests[i].data);
	
	}
	
	t = CEL_CONTENT_PCCLIENT_STD;
	raw_put(&t, 1);
	tmp = htonl(5 + 5 + 4 + event_size);
	raw_put((unsigned char *) &tmp, 4);
	tmp = htonl(event_type);
	tlv_put(PCCLIENT_EVENT_TYPE, 4, (unsigned char *) &tmp);
	tlv_put(PCCLIENT_EVENT_CONTENT, event_size, (unsigned char *)event_data);

	return true;
}

bool read_specid(void) {
	uint32_t pcr;
	uint32_t event_type;
	uint8_t sha1[SHA1_HASH_LEN];
	uint32_t event_size;
	uint8_t *event_data;
	uint32_t tmp;
	uint8_t t;

	if (!read_uint32(&pcr))
	        return false;
	if (!read_uint32(&event_type))
	        return false;
	if (read(0, sha1, SHA1_HASH_LEN) != SHA1_HASH_LEN)
	        return false;
	if (!read_uint32(&event_size))
	        return false;
	if (!(event_data = malloc(event_size)))
	        return false;
	if (read(0, event_data, event_size) != event_size)
	        return false;

	/* CEL_SEQ */
	tmp = htonl(seqs[pcr]++);
	tlv_put(CEL_SEQ, 4, (unsigned char *) &tmp);
	
	/* CEL_PCR */
	tmp = htonl(pcr);
	tlv_put(CEL_PCR, 4, (unsigned char *) &tmp);
	
	/* CEL_DIGEST */
	t = CEL_DIGEST;
	raw_put(&t, 1);
	tmp = htonl(SHA1_HASH_LEN + 5);
	raw_put((unsigned char *)&tmp, 4);
	tlv_put(TPM2_ALG_SHA1, SHA1_HASH_LEN, (unsigned char *)sha1);

	/* CEL_CONTENT */
	t = CEL_CONTENT_PCCLIENT_STD;
	raw_put(&t, 1);
	tmp = htonl(event_size + 5 + 5 + 4);
	raw_put((unsigned char *) &tmp, 4);
	tmp = htonl(event_type);
	tlv_put(PCCLIENT_EVENT_TYPE, 4, (unsigned char *) &tmp);
	tlv_put(PCCLIENT_EVENT_CONTENT, event_size, (unsigned char *)event_data);	

	return true;
}

/* Read one specid event, and then all event2 records. */
int main(int argc, char *argv[]) {
	if (!read_specid())
	        return -1;
	while (read_event2())
	        ;
}
