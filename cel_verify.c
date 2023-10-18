/*
 * cel_verify
 *
 * Copyright (C) 2023
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <asm/byteorder.h>
#include <dirent.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "cel.h"
#include "cel_verify.h"
#include "pcclient_verify.h"
#include "ima_template_verify.h"

int verbose = 0;
struct rim rims[MAX_HASHES];
int have_hashes = 0;

/* RIM hashfiles have lines of ascii hex sha256 followed by ascii pathname */
static int read_hashfile(char *path) {
	FILE *f;
	char line[ENTRY_LINE_MAX], a, b;
	int entry = 0;
	int i;

	memset(rims, 'A', sizeof(rims));
	f = fopen(path, "r");
	if (!f)
	        return 0;
	while (fgets(line, sizeof(line), f)) {
	        line[strlen(line) - 1] = '\0'; // get rid of trailine \n
	        for (i=0; i<32; i++) {
	                a = line[2*i];
	                b = line[2*i +1];
	                a = (a <= '9') ? a - '0' : (a & 0x7) + 9;
	                b = (b <= '9') ? b - '0' : (b & 0x7) + 9;
	                rims[entry].sha256[i] = (a << 4) + b;
	        }
	        strncpy(rims[entry].name, line + 65, MAX_FNAME);
	        memset(line, 0, ENTRY_LINE_MAX);
	        entry++;
	}
	fclose(f);
	return 1;
}

int verify_by_rim(uint8_t *h) {
	int i;

	if (!have_hashes)
	        return -1;

	for (i = 0; i < MAX_HASHES; i++) {
	        if (memcmp(rims[i].sha256, h, SHA256_HASH_LEN) == 0)
	                return i;
	}
	return -1;
}

int calculate_sha256(uint8_t *hash, uint8_t *v, int l)
{
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
	unsigned int len = 0;

	mdctx = EVP_MD_CTX_new();
	md = EVP_MD_fetch(NULL, "SHA256", NULL);
	if(!md) {
	        printf("Did not fetch SHA256\n");
	        return -1;
	}
	EVP_DigestInit_ex2(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, v, l);
	EVP_DigestFinal_ex(mdctx, hash, &len);
	EVP_MD_free(md);
	EVP_MD_CTX_free(mdctx);
	return 0;
}

int verify_sha256(uint8_t *hash, uint8_t *v, int l)
{
	uint8_t calculated[SHA256_HASH_LEN];
	int r;

	if ((r = calculate_sha256(calculated, v, l)) != 0)
	        return r;
	return (memcmp(hash, calculated, SHA256_HASH_LEN));
}

static void extend_sha256(uint8_t *pcr, uint8_t *v, int l)
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
	EVP_DigestUpdate(mdctx, pcr, SHA256_HASH_LEN);
	EVP_DigestUpdate(mdctx, v, l);
	EVP_DigestFinal_ex(mdctx, pcr, &len);
	EVP_MD_free(md);
	EVP_MD_CTX_free(mdctx);
}

static void extend_sha1(uint8_t *pcr, uint8_t *v, int l)
{
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
	unsigned int len = 0;

	mdctx = EVP_MD_CTX_new();
	md = EVP_MD_fetch(NULL, "SHA1", NULL);
	if(!md) {
	        printf("Did not fetch SHA1\n");
	        return;
	}
	EVP_DigestInit_ex2(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, pcr, SHA1_HASH_LEN);
	EVP_DigestUpdate(mdctx, v, l);
	EVP_DigestFinal_ex(mdctx, pcr, &len);
	EVP_MD_free(md);
	EVP_MD_CTX_free(mdctx);		
}

static void calc_pcrs(struct record *r,
		      uint8_t pcr_sha1[NUM_PCRS][MAX_DATA_HASH],
		      uint8_t pcr_sha256[NUM_PCRS][MAX_DATA_HASH])
{
	int pcr;

	pcr = ntohl(*(uint32_t *)(r->pcr->v));
	if (r->have_sha256)
	        extend_sha256(pcr_sha256[pcr], r->sha256, SHA256_HASH_LEN);
	if (r->have_sha1)
	        extend_sha1(pcr_sha1[pcr], r->sha1, SHA1_HASH_LEN);
}

void hexdump(uint8_t *b, int l)
{
	int i,j;
	for (i=0, j=0; i < l; i++){
		printf("%02X",b[i]);
		if (j++ == 32){
			printf("\n");
			j = 0;
		}
	}
	printf(" ");
}

void ascii_dump(uint8_t *b, int l)
{
	int i, j;
	printf(":");
	for (i=0, j=0; i < l; i++) {
		if (b[i] > 31 && b[i] < 127)
			printf("%c",b[i]);
		else
			printf(".");
		if (j++ == 64){
			printf("\n");
			j = 0;
		}
	}
	printf(" ");
}

static void display_cel_seq(struct tlv *tlv)
{
	uint32_t seq;
	
	seq = ntohl(*(uint32_t *)(tlv->v));
	printf("SEQ %d ", seq);
}

static void display_cel_pcr(struct tlv *tlv)
{
	uint32_t pcr;
	
	pcr = ntohl(*(uint32_t *)(tlv->v));
	printf("PCR %d ", pcr);
}

static void display_digest(struct tlv *tlv)
{
	if (tlv->t == TPM_ALG_SHA1) {
		printf("SHA1 ");
		hexdump(tlv->v, tlv->l);
		printf("\n");
	} else if (tlv->t == TPM_ALG_SHA256) {
		printf("SHA256 ");
		hexdump(tlv->v, tlv->l);
		printf("\n");
	} else {
		printf("Unknown Digest %02d %02d\n",tlv->t, tlv->l);
		hexdump(tlv->v, tlv->l);
	}
}

static void display_cel_digest(struct tlv *tlv)
{
	struct tlv *tmp;
	int pos;

	printf("DIGESTS ");
	/* Walk through the one or more nested digest tlv's.
	 * Lengths in the nested TLV's were fixed in read.
	 */
	for (pos=0; pos + 5 < tlv->l; ) {
		tmp = (struct tlv *)((unsigned char *)tlv + pos + 5);		
		display_digest(tmp);
		pos += tmp->l + 5;
	}
}

static void display_cel_content_mgt(struct tlv *tlv)
{
	printf("CEL_CONTENT_MGT: type %d, len %d, value ", tlv->t, tlv->l);
	hexdump(tlv->v, tlv->l);	
}

static void display_cel_content_systemd(struct tlv *tlv) {
	printf("CEL_CONTENT_SYSTEMD %s ", tlv->v);
}

static void display_cel_content(struct tlv *tlv)
{
	switch (tlv->t) {
		case CEL_CONTENT_MGT :
			display_cel_content_mgt(tlv);
			break;
		
		case CEL_CONTENT_PCCLIENT_STD :
			display_pcclient_content(tlv);
			break;
		
		case CEL_CONTENT_IMA_TEMPLATE :
			display_ima_template_content(tlv);
			break;
		
		case CEL_CONTENT_IMA_TLV :
			//display_ima_tlv_content(tlv);
			break;
		
		case CEL_CONTENT_SYSTEMD :
		        display_cel_content_systemd(tlv);
		        break;
		
		default :
			printf("Unsupported CEL contenttype %d\n", tlv->t);
	}
}

static void display_record(struct record *r)
{
	display_cel_seq(r->seq);
	display_cel_pcr(r->pcr);
	if (verbose)
	        display_cel_digest(r->digests);
	display_cel_content(r->content);
	if (r->verified_digests)
	        printf("Verified by digest ");
	if (r->verified_rim >= 0)
	        printf("Verified by RIM %s ", rims[r->verified_rim].name);
	printf("\n");
	if (verbose)
	        printf("\n");
}

/* for systemd content check its hash against digest. No need to check RIM*/
void verify_systemd_content(struct record *r) {
	if (verify_sha256(r->sha256, r->content->v, r->content->l) == 0)
	        r->verified_digests = 1;
}

/* allocate and read in a TLV from stdin */
static struct tlv * read_cel_tlv(void)
{
	uint8_t t = 0;
	uint32_t l = 0;
	struct tlv *tlv;
	
	if (read(0, (void *)&(t), 1) != 1)
		return NULL;
	if (read(0, (void *)&(l), 4) != 4)
		return NULL;
	l = ntohl(l);
	if (l > (MAX_TLV - 5)){
		printf("Invalid TLV length: %08X\n", l);
		return NULL;
	}	
	tlv = (struct tlv *)malloc(l+5);
	if (!tlv) {
		printf("Malloc failed while reading event\n");
		return NULL;
	}
	tlv->t = t;
	tlv->l = l;
	if (read(0, (void *)(tlv->v), l) != l){
		free(tlv);
		return NULL;
	}
	return tlv;
}

static void fix_digest(struct record *r) {
	struct tlv *t, *tmp;
	int pos;

	t = r->digests;
	/* Walk through the one or more nested digest tlv's.
	 * Lengths in the nested TLV's must be fixed.
	 */
	for (pos=0; pos + 5 < t->l; ) {
		tmp = (struct tlv *)((unsigned char *)t + pos + 5);
		tmp->l = ntohl(tmp->l);	
		if (tmp->t == TPM_ALG_SHA256) {
		        memcpy(r->sha256, tmp->v, SHA256_HASH_LEN);
		        r->have_sha256 = 1;
		}
		if (tmp->t == TPM_ALG_SHA1) {
		        memcpy(r->sha1, tmp->v, SHA1_HASH_LEN);
		        r->have_sha1 = 1;
		}
		pos += tmp->l + 5;
	}
}

/* read and return one record (four top level tlv)
 * Be sure to fix length endianness of all top and nested tlvs.
 */
static struct record * read_record(void)
{
	struct record *record;
	
	record = (struct record *) malloc(sizeof(struct record));
	if (!record)
		return NULL;
	record->seq = read_cel_tlv();
	if (!record->seq || record->seq->t != CEL_SEQ)
		return NULL;
	record->pcr = read_cel_tlv();
	if (!record->pcr || record->pcr->t != CEL_PCR)
		return NULL;
	record->digests = read_cel_tlv();
	if (!record->digests || record->digests->t != CEL_DIGEST)
		return NULL;
	fix_digest(record);
	record->content = read_cel_tlv();
	if(!record->content)
		return NULL;
	if (record->content->t == CEL_CONTENT_PCCLIENT_STD)
	        fix_pcclient_content(record->content);
	if (record->content->t == CEL_CONTENT_IMA_TEMPLATE) {
	        fix_ima_template_content(record->content);
	        fix_ima_template_sha1(record);
	}
	record->verified_rim = -1;
	return record;
}

/* read an entire event log from stdin, and return the head record */
static struct record_list * read_list(void)
{
	struct record *r;
	struct record_list *head = NULL, *current = NULL, *new;
	
	while ((r = read_record())){
		new = (struct record_list *)malloc(sizeof(struct record_list));
		new->record = r;
		new->next = NULL;
		if (!head)
			head = new;
		else
			current->next = new;
		current = new;	
	}	
			
	return head;
}

/*
 * cel_verify - verify a CEL-TLV formatted event log
 *              cel_verify [-p pcrbinfile][-h hashfile][-v]
 *              reads from stdin, sends to stdout
 *              pcrbinfile is file from which to read target pcrs in binary form.
 *              Create this with "tpm2_pcrread -o <path> sha256"
 *              hashbinfile is ascii lines with ascii-hex sha256 hash followed by text description.
 */
int main(int argc, char *argv[])
{
	static uint8_t pcr_sha1[NUM_PCRS][MAX_DATA_HASH];
	static uint8_t pcr_sha256[NUM_PCRS][MAX_DATA_HASH];
	static uint8_t pcrs[NUM_PCRS * SHA256_HASH_LEN];
	struct record_list *head, *rl;
	int c, pcr, fd, have_pcrs = 0;
	size_t s;
	char *pcrbinfile = NULL;
	char *hashfile = NULL;
	
	while ((c = getopt(argc, argv, "p:h:v")) != -1) {
	        switch (c) {
	                case 'p':
	                        pcrbinfile = optarg;
	                break;
	                case 'h':
	                        hashfile = optarg;
	                break;
	                case 'v':
	                        verbose = 1;
	        }
	}

	/* read in the whole event log as records of tlvs */
	head = read_list();

	/* calculate the effective pcr values from the log */
	for (rl = head; rl != NULL; rl = rl->next)
		calc_pcrs(rl->record, pcr_sha1, pcr_sha256);
		
	/* If sha256 target pcr values are available, read them in */
	if (pcrbinfile) {
	        fd = open(pcrbinfile, O_RDONLY);
	        if (fd != -1) {
	                s = read(fd, (void *)pcrs, sizeof(pcrs));
	                if (s == sizeof(pcrs))
	                        have_pcrs = 1;
	        }
	}
	
	/* check and display calculated PCR values */
	printf("Verifying Event Log Against PCRs\n\n");
	for (pcr = 0; pcr < NUM_PCRS; pcr++) {
		printf("PCR %02d SHA256: ", pcr);
		hexdump(pcr_sha256[pcr], SHA256_HASH_LEN);
		if (have_pcrs) {
		        if (memcmp(pcr_sha256[pcr], &pcrs[pcr * SHA256_HASH_LEN],
		            SHA256_HASH_LEN) == 0)
		                printf(" MATCHES");
		        else
		                printf(" NO MATCH");
		}
		printf("\n");
	}
	
	/* verify each record's content against its digests and RIM hashes */
	printf("\nVerifying each record against digest or RIM\n\n");
	if (hashfile)
	        have_hashes = read_hashfile(hashfile);
	
	for (rl = head; rl != NULL; rl = rl->next)
	        if (rl->record->content->t == CEL_CONTENT_PCCLIENT_STD)
	                verify_pcclient_content(rl->record);
	        else if (rl->record->content->t == CEL_CONTENT_SYSTEMD)
	                verify_systemd_content(rl->record);
	        else if (rl->record->content->t == CEL_CONTENT_IMA_TEMPLATE)
	                verify_ima_template_content(rl->record);
	                	
	/* walk the list and check entry signatures against RIM PK - TODO*/	
		
	/* walk the list and display records */	
	if (verbose)
	        printf("Dumping all event records\n\n");
	else
	        printf("Summarizing all events\n\n");

	for (rl = head; rl != NULL; rl = rl->next)
		display_record(rl->record);	
}
