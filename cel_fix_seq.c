/*
 * cel_fix_seq - read a CEL event log in from stdin, and output 
 *               a log with fixed sequence numbers
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

#include "cel.h"
#define MAX_TLV 32000
#define MAX_PCR 24

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
};

struct record_list {
	struct record *record;
	struct record_list *next;
};

static uint32_t seq[MAX_PCR];

static void fixup_pcr(struct record* record) {
	uint32_t pcrnum, seqnum;
	
	pcrnum = ntohl(*(uint32_t *)(record->pcr->v));
	seqnum = seq[pcrnum]++;
	*((uint32_t *)(record->seq->v)) = htonl(seqnum);
}

static void put_cel_tlv(struct tlv *tlv) {
	uint32_t nl;
	ssize_t ret;
	
	nl = htonl(tlv->l);
	ret = write(1, &tlv->t, 1);
	ret = write(1, &nl, 4);
	ret = write(1, tlv->v, tlv->l);
	(void)ret;
}

static void put_record(struct record *record) {
        put_cel_tlv(record->seq);
        put_cel_tlv(record->pcr);
        put_cel_tlv(record->digests);
        put_cel_tlv(record->content);
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
		fprintf(stderr, "Invalid TLV length: %08X\n", l);
		return NULL;
	}	
	tlv = (struct tlv *)malloc(l+5);
	if (!tlv) {
		fprintf(stderr, "Malloc failed while reading event\n");
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
	record->content = read_cel_tlv();
	if(!record->content)
		return NULL;

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

int main(int argc, char *argv[])
{
	struct record_list *head, *rl;
        memset(seq, 0, sizeof(seq));
        
	/* read in the whole event log as records of tlvs */
	head = read_list();
	for (rl = head; rl != NULL; rl = rl->next)
	        fixup_pcr(rl->record);
	for (rl = head; rl != NULL; rl = rl->next)
		put_record(rl->record);	
}
