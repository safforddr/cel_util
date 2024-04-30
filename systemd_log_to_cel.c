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
#include <ctype.h>
#include <tss2/tss2_tpm2_types.h>
#include "cel.h"
#include <json-c/json.h>

/* sequence numbers are per PCR */
uint32_t seqs[TPM2_MAX_PCRS];
int32_t pcr;
const char *hashAlg, *digest, *content;

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

void dhextobin(unsigned char *bin, const char *digest) {
        int i;
        char ch1, ch2;
        unsigned char un1, un2;
        for (i=0; i<32; i++) {
                ch1 = tolower(digest[i*2]);
                ch2 = tolower(digest[i*2 + 1]);
                un1 = (ch1 >= 'a')? (ch1 - 'a' + 10): (ch1 - '0');
                un2 = (ch2 >= 'a')? (ch2 - 'a' + 10): (ch2 - '0');
                bin[i] = (un1 << 4) + un2;                
        }
}

/* digest is hex encoded, banks is "sha256" */
void put_digests(const char *digest, const char *banks) {
	uint8_t t;
	uint32_t tmp;
	int len;

	if (strstr(banks, "sha256")) {
	        unsigned char bin[SHA256_HASH_LEN];
	        len = strlen(digest);
	        if (len == 64)
	                dhextobin(bin, digest);
	        else
	                memset(bin, 0, SHA256_HASH_LEN);
	            
	        t = CEL_DIGEST;
	        raw_put(&t, 1);
	        tmp = htonl(SHA256_HASH_LEN + 5);
	        raw_put((unsigned char *)&tmp, 4);
		t = TPM2_ALG_SHA256;
	        tlv_put(t, SHA256_HASH_LEN, (unsigned char *)bin);   	
	}
}

void put_systemd_cel(int pcr, const char *hashAlg, const char *digest, const char *content) {
	uint32_t tmp;
        
	tmp = htonl(seqs[pcr]++);
	tlv_put(CEL_SEQ, 4, (unsigned char *) &tmp);
	tmp = htonl(pcr);
	tlv_put(CEL_PCR, 4, (unsigned char *) &tmp);
	put_digests(digest, hashAlg);	
	tlv_put(CEL_CONTENT_SYSTEMD, strlen(content), (uint8_t *)content);	
}

/* check leaf objects for needed keys */
void get_json_value(json_object *jobj, char *key){
        
        if(!strncmp(key, "pcr", 3)) {
                pcr = json_object_get_int(jobj);                 
        } else if(!strncmp(key, "hashAlg", 7)) {
                hashAlg = json_object_get_string(jobj);           
        } else if(!strncmp(key, "digest", 3)) {
                digest = json_object_get_string(jobj);              
        } else if(!strncmp(key, "string", 7)) {
                content = json_object_get_string(jobj);            
        }
}

void json_parse_array(json_object *jobj, char *key) {
      void json_parse(json_object * jobj); 
      enum json_type type;

      json_object *jarray = jobj;
      if(key) {
              jarray = json_object_object_get(jobj, key);
      }

      int arraylen = json_object_array_length(jarray);
      int i;
      json_object * jvalue;

      for (i=0; i< arraylen; i++){
              jvalue = json_object_array_get_idx(jarray, i);
              type = json_object_get_type(jvalue);
              if (type == json_type_array) {
                      json_parse_array(jvalue, NULL);
              } else if (type != json_type_object) {
                      get_json_value(jvalue, key);
              } else {
                      json_parse(jvalue);
              }
      }
}

/*Parsing the json object*/
void json_parse(json_object * jobj) {
        enum json_type type;
        
        json_object_object_foreach(jobj, key, val) {
                type = json_object_get_type(val);
                switch (type) {
                        case json_type_boolean: 
                        case json_type_double: 
                        case json_type_int: 
                        case json_type_string: 
                                get_json_value(val, key);
                                break; 
                        case json_type_object:
                                jobj = json_object_object_get(jobj, key);
                                json_parse(jobj); 
                                break;
                        case json_type_array: 
                                json_parse_array(jobj, key);
                                break;
                        default:
                                break;
                }
        }
} 

int main() {
        char *line = NULL;
        size_t len = 0;
        size_t r = 0;
        
        
        /* read systemd tpm2 json events from stdin */
        while((r = getline(&line, &len, stdin) > 0)) {     
                /* parse this json line */
                json_object * jobj = json_tokener_parse(line+1);  // skip weird leading '1e' character
                if(!jobj)
                        continue;
                pcr = 0;
                hashAlg = NULL;
                digest = NULL;
                content = NULL;
                json_parse(jobj);
                
                if (pcr && digest && hashAlg && content)
                        put_systemd_cel(pcr, hashAlg, digest, content);
                        
                free(line);
                line = NULL;
                len = 0;
        }
}
