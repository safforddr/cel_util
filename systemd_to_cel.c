/*
 * systemd_to_cel
 *
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * Find journal entries for PCR extension, and translate them to CEL.
 * Reads from journal log using libsystemd, writes to stdout.
 */
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <tss2/tss2_tpm2_types.h>
#include "cel.h"

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

static void get_sha256(uint8_t *digest, uint8_t *v, int l)
{
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
	unsigned int len = 0;

	mdctx = EVP_MD_CTX_new();
	md = EVP_MD_fetch(NULL, "SHA256", NULL);
	if(!md) {
	        printf("Did not fetch SHA256\n");
	        return;
	}
	EVP_DigestInit_ex2(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, v, l);
	EVP_DigestFinal_ex(mdctx, digest, &len);
	EVP_MD_free(md);
	EVP_MD_CTX_free(mdctx);
}

/* for now, just do sha256 */
void put_digests(char *data, char *banks) {
	uint8_t t;
	uint32_t tmp;
	uint8_t digest[SHA256_HASH_LEN];
	int len;

	if (strstr(banks, "sha256")) {
	        len = strlen(data);
	        get_sha256(digest, (uint8_t *)data, len);
	        t = CEL_DIGEST;
	        raw_put(&t, 1);
	        tmp = htonl(SHA256_HASH_LEN + 5);
	        raw_put((unsigned char *)&tmp, 4);
		t = TPM2_ALG_SHA256;
	        tlv_put(t, SHA256_HASH_LEN, (unsigned char *)digest);   	
	}
}

void put_systemd_cel(char *pcr, char *data, char *banks){
	uint32_t pcrnum, tmp;

	pcrnum = atol(pcr);
	tmp = htonl(seqs[pcrnum]++);
	tlv_put(CEL_SEQ, 4, (unsigned char *) &tmp);
	tmp = htonl(pcrnum);
	tlv_put(CEL_PCR, 4, (unsigned char *) &tmp);
	put_digests(data, banks);	
	tlv_put(CEL_CONTENT_SYSTEMD, strlen(data), (uint8_t *)data);	
}

bool get_substr(const char *d, const char *prefix, char *dst) {
	char *p;

	if (!(p = strstr(d, prefix)))
	        return false;
	for (p += strlen(prefix);((*p != ' ') && (*p != '\'') && (*p != ')')); p++)
	        *(dst++)  = *p;
	*dst = '\0';
	return true;
}

/*
 * We should probably do this with proper journal fields:
 *     "MESSAGE_ID=" SD_MESSAGE_TPM_PCR_EXTEND_STR,
 *     "MEASURING="
 *     "PCR="
 *     "BANKS="
 * For now we will just grab the fields from the MESSAGE:
 * We have a journal "Extended" entry of the form:
 *     MESSAGE=Extended PCR index 11 with 'sysinit' (banks sha256).
 * Translate this to CEL with content type CEL_CONTENT_SYSTEMD
 */
void extended(size_t l, const char *d) {
	char pcr[3], data[64], banks[64];

	if (!get_substr(d, "index ", pcr))
	        return;
	if (!get_substr(d, "with \'", data))
	        return;
	if (!get_substr(d, "banks ", banks))
	        return;

	put_systemd_cel(pcr, data, banks);
}

int main(int argc, char *argv[]) {
	int r, s;
	sd_journal *j;
	char boot_id[64];
	const char *b, *d;
	size_t l, m;
	
	r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
	if (r < 0) {
		errno = -r;
		fprintf(stderr, "Failed to open journal: %m\n");
		return 1;
	}
	
	/* find latest boot_id - there's probably a faster way...*/
	SD_JOURNAL_FOREACH(j) {
	        s = sd_journal_get_data(j, "_BOOT_ID", (const void **)&b, &m);
	        if (s < 0) {
	                errno = -s;
		        fprintf(stderr, "Failed to read boot_id field: %m\n");
		        continue;
	        }
	        strncpy(boot_id, b, m);
	}
	
	/* get all messages for latest boot_id */
	SD_JOURNAL_FOREACH(j) {    		
		s = sd_journal_get_data(j, "_BOOT_ID", (const void **)&b, &m);
		if (s < 0) {
			errno = -s;
			fprintf(stderr, "Failed to read boot_id field: %m\n");
			continue;
		}
		if (strncmp(boot_id, b, m))
		        continue;

		r = sd_journal_get_data(j, "MESSAGE", (const void **)&d, &l);
		if (r < 0) {
			errno = -r;
			fprintf(stderr, "Failed to read message field: %m\n");
			continue;
		}
		if (!strncmp(d, "MESSAGE=Extended", 16))
		        extended(l, d);
	}
	sd_journal_close(j);
	return 0;
}
