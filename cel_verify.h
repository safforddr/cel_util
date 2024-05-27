/*
 * cel-verify.h
 *
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

/* All TLV lengths are in network byte order (big endian).
 * When reading in the top level CEL TLV's, we translate
 * these to host order. Nested digests and content TLV's
 * are not automatically converted, and must be handled
 * as they are parsed. Digests of contents in general
 * must be on the network byte order values.
 */

#define IMA_PCR		10
#define	NUM_PCRS 	16
#define SHA1_HASH_LEN   20
#define SHA256_HASH_LEN 32
#define MAX_DATA_HASH 	32	/* sha-256 */
#define MAX_DATA_SIG 	256	/* 2048 bit RSA */
#define MAX_TLV 	32000   /* dbx variables have gotten BIG */
#define ENTRY_LINE_MAX	2048    /* for RIM file lines */
#define MAX_FNAME	(2048 - 65)
#define MAX_HASHES	256     /* max lines in RIM file */

struct __attribute__ ((__packed__)) tlv {
	uint8_t t;
	uint32_t l;
	uint8_t v[];
};

struct record {
	struct tlv *seq;
	struct tlv *pcr;
	struct tlv *digests;
	struct tlv *content;
	int have_sha256;
	uint8_t sha256[SHA256_HASH_LEN];
	int have_sha1;
	uint8_t sha1[SHA1_HASH_LEN];
	int verified_digests;
	int verified_rim;
	int verified_imasig;
};

struct record_list {
	struct record *record;
	struct record_list *next;
};

struct rim {
	uint8_t sha256[SHA256_HASH_LEN];
	char name[MAX_FNAME];
};

void hexdump(uint8_t *b, int l);
void ascii_dump(uint8_t *b, int l);
extern int verbose;
int verify_sha256(uint8_t *hash, uint8_t *v, int l);
int verify_by_rim(uint8_t *hash);
int calculate_sha256(uint8_t *hash, uint8_t *v, int l);
