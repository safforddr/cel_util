/*
 * IMA_TEMPLATE (ima-sig) support functions for cel_verify
 *
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * Derived in part from libimaevm.c, part of ima-evm-utils,
 * written by Dmitry Kasatkin <dmitry.kasatkin@nokia.com>
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
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include "cel.h"
#include "cel_verify.h"
#include "pcclient_verify.h"

#define __packed __attribute__((packed))

enum pkey_hash_algo {
	PKEY_HASH_MD4,
	PKEY_HASH_MD5,
	PKEY_HASH_SHA1,
	PKEY_HASH_RIPE_MD_160,
	PKEY_HASH_SHA256,
	PKEY_HASH_SHA384,
	PKEY_HASH_SHA512,
	PKEY_HASH_SHA224,
	PKEY_HASH__LAST
};

const char *const pkey_hash_algo[PKEY_HASH__LAST] = {
	[PKEY_HASH_MD4]		= "md4",
	[PKEY_HASH_MD5]		= "md5",
	[PKEY_HASH_SHA1]	= "sha1",
	[PKEY_HASH_RIPE_MD_160]	= "rmd160",
	[PKEY_HASH_SHA256]	= "sha256",
	[PKEY_HASH_SHA384]	= "sha384",
	[PKEY_HASH_SHA512]	= "sha512",
	[PKEY_HASH_SHA224]	= "sha224",
};
enum evm_ima_xattr_type {
	IMA_XATTR_DIGEST = 0x01,
	EVM_XATTR_HMAC,
	EVM_IMA_XATTR_DIGSIG,
	IMA_XATTR_DIGEST_NG,
	EVM_XATTR_PORTABLE_DIGSIG,
	IMA_VERITY_DIGSIG,
};

enum digsig_version {
	DIGSIG_VERSION_1 = 1,
	DIGSIG_VERSION_2,
	DIGSIG_VERSION_3	/* hash of ima_file_id struct (portion used) */
};

/*
 * ima v2 signature format
 * Note: The initial "Type" byte is not included.
 */
struct signature_v2_hdr {
	uint8_t version;
	uint8_t	hash_algo;
	uint32_t keyid;
	uint16_t sig_size;
	uint8_t sig[0];
} __packed;

struct signature_hdr {
	uint8_t version;	/* signature format version */
	uint32_t timestamp;	/* signature made */
	uint8_t algo;
	uint8_t hash;
	uint8_t keyid[8];
	uint8_t nmpi;
	char mpi[0];
} __packed;

enum digest_algo {
	DIGEST_ALGO_SHA1,
	DIGEST_ALGO_SHA256,
	DIGEST_ALGO_MAX
};

struct public_key_entry {
	struct public_key_entry *next;
	uint32_t keyid;
	char name[9];
	EVP_PKEY *key;
};

/* these pointers are not persistent, as they point to within the current tlv */
struct ima_sig_content {
        uint8_t *filename;
        int filename_len;
        uint8_t *filehash;
        int filehash_len;
        uint8_t *filesig;
        int filesig_len;
};

#define HASH_MAX_DIGESTSIZE 64	/* kernel HASH_MAX_DIGESTSIZE is 64 bytes */
#define MAX_DIGEST_SIZE		64
#define	DATA_SIZE	        4096
#define DEFAULT_HASH_ALGO       "sha256"
#define log_err(fmt, args...)	\
	({fprintf(stderr, fmt, ##args); })
static struct public_key_entry *g_public_keys = NULL;	

void calc_keyid_v2(uint32_t *keyid, char *str, EVP_PKEY *pkey);
int imaevm_get_hash_algo(const char *algo);
static int read_keyid_from_cert(uint32_t *keyid_be, const char *certfile,
				int try_der);

const char *imaevm_hash_algo_by_id(int algo)
{
	if (algo < PKEY_HASH__LAST)
		return pkey_hash_algo[algo];

	log_err("digest %d not found\n", algo);
	return NULL;
}

/* Output all remaining openssl error messages. */
static void output_openssl_errors(void)
{
	while (ERR_peek_error()) {
		char buf[256];
		/* buf must be at least 256 bytes long according to man */

		ERR_error_string(ERR_get_error(), buf);
		log_err("openssl: %s\n", buf);
	}
}

static int add_file_hash(const char *file, EVP_MD_CTX *ctx)
{
	uint8_t *data;
	int err = -1, bs = DATA_SIZE;
	off_t size, len;
	FILE *fp;
	struct stat stats;

	fp = fopen(file, "r");
	if (!fp) {
		log_err("Failed to open: %s\n", file);
		return -1;
	}

	data = malloc(bs);
	if (!data) {
		log_err("malloc failed\n");
		goto out;
	}

	if (fstat(fileno(fp), &stats) == -1) {
		log_err("Failed to fstat: %s (%s)\n", file, strerror(errno));
		goto out;
	}

	for (size = stats.st_size; size; size -= len) {
		len = MIN(size, bs);
		if (fread(data, len, 1, fp) != 1) {
			if (ferror(fp)) {
				log_err("fread() failed\n\n");
				goto out;
			}
			break;
		}
		if (!EVP_DigestUpdate(ctx, data, len)) {
			log_err("EVP_DigestUpdate() failed\n");
			err = 1;
			goto out;
		}
	}
	err = 0;
out:
	fclose(fp);
	free(data);

	return err;
}

int ima_calc_hash2(const char *file, const char *hash_algo, uint8_t *hash)
{
	const EVP_MD *md;
	struct stat st;
	EVP_MD_CTX *pctx;
	unsigned int mdlen;
	int err;

	pctx = EVP_MD_CTX_new();

	/*  Need to know the file length */
	err = lstat(file, &st);
	if (err < 0) {
		log_err("Failed to stat: %s\n", file);
		goto err;
	}

	md = EVP_get_digestbyname(hash_algo);
	if (!md) {
		log_err("EVP_get_digestbyname(%s) failed\n", hash_algo);
		err = 1;
		goto err;
	}

	err = EVP_DigestInit(pctx, md);
	if (!err) {
		log_err("EVP_DigestInit() failed\n");
		err = 1;
		goto err;
	}

	switch (st.st_mode & S_IFMT) {
	case S_IFREG:
		err = add_file_hash(file, pctx);
		break;
	default:
		log_err("Unsupported file type (0x%x)", st.st_mode & S_IFMT);
		err = -1;
		goto err;
	}

	if (err)
		goto err;

	err = EVP_DigestFinal(pctx, hash, &mdlen);
	if (!err) {
		log_err("EVP_DigestFinal() failed\n");
		err = 1;
		goto err;
	}
	err = mdlen;
err:
	if (err == 1)
		output_openssl_errors();
	return err;
}

int ima_calc_hash(const char *file, uint8_t *hash)
{
	return ima_calc_hash2(file, DEFAULT_HASH_ALGO, hash);
}

EVP_PKEY *read_pub_pkey(const char *keyfile, int x509)
{
	FILE *fp;
	EVP_PKEY *pkey = NULL;
	struct stat st;

	if (!keyfile)
		return NULL;

	fp = fopen(keyfile, "r");
	if (!fp) {
		return NULL;
	}

	if (fstat(fileno(fp), &st) == -1) {
		log_err("Failed to fstat key file: %s\n", keyfile);
		goto out;
	}

	if ((st.st_mode & S_IFMT) != S_IFREG) {	
		log_err("Key file is not regular file: %s\n", keyfile);
		goto out;
	}

	if (x509) {
		X509 *crt = d2i_X509_fp(fp, NULL);

		if (!crt) {
			log_err("Failed to d2i_X509_fp key file: %s\n",
				keyfile);
			goto out;
		}
		pkey = X509_extract_key(crt);
		X509_free(crt);
		if (!pkey) {
			log_err("Failed to X509_extract_key key file: %s\n",
				keyfile);
			goto out;
		}
	} else {
		pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
		if (!pkey)
			log_err("Failed to PEM_read_PUBKEY key file: %s\n",
				keyfile);
	}

out:
	if (!pkey)
		output_openssl_errors();
	fclose(fp);
	return pkey;
}

static EVP_PKEY *find_keyid(struct public_key_entry *public_keys,
			    uint32_t keyid)
{
	struct public_key_entry *entry, *tail = public_keys;
	int i = 1;

	for (entry = public_keys; entry; entry = entry->next) {
		if (entry->keyid == keyid)
			return entry->key;
		i++;
		tail = entry;
	}

	/* add unknown keys to list */
	entry = calloc(1, sizeof(struct public_key_entry));
	if (!entry) {
		perror("calloc");
		return 0;
	}
	entry->keyid = keyid;
	if (tail)
		tail->next = entry;
	else
		public_keys = entry;
	log_err("key %d: %x (unknown keyid)\n", i, __be32_to_cpup(&keyid));
	return 0;
}

void imaevm_free_public_keys(struct public_key_entry *public_keys)
{
	struct public_key_entry *entry = public_keys, *next;

	while (entry) {
		next = entry->next;
		if (entry->key)
			free(entry->key);
		free(entry);
		entry = next;
	}
}

int imaevm_init_public_keys(const char *keydir,
			    struct public_key_entry **public_keys)
{
	struct public_key_entry *entry;
	DIR *d;
	struct dirent *dir;
	char keyfile[1024];
	int err;
	
	d = opendir(keydir);
	if (!d)
	        return -EINVAL;

	if (!public_keys)
		return -EINVAL;

	*public_keys = NULL;

	while ((dir = readdir(d)) != NULL) {
	        if (dir->d_type != DT_REG)
	                continue;
	                
                snprintf(keyfile, 1024, "%s/%s", keydir, dir->d_name);

		entry = malloc(sizeof(struct public_key_entry));
		if (!entry) {
			perror("malloc");
			err = -ENOMEM;
			break;
		}
                //printf("Attempting to load keyfile %s\n",keyfile);
		entry->key = read_pub_pkey(keyfile, 1);
		if (!entry->key) {
			free(entry);
			printf("read_pub_pkey returned NULL\n");
			continue;
		}

		if (read_keyid_from_cert(&entry->keyid, keyfile, 1) < 0)
			calc_keyid_v2(&entry->keyid, entry->name, entry->key);

		sprintf(entry->name, "%x", __be32_to_cpup(&entry->keyid));
		//log_err("key %d: %s %s\n", i++, entry->name, keyfile);
		entry->next = *public_keys;
		*public_keys = entry;
	}

	if (err < 0)
		imaevm_free_public_keys(*public_keys);
	return err;
}

void init_public_keys(const char *keydir)
{
	imaevm_init_public_keys(keydir, &g_public_keys);
}

/*
 * Verify a signature, prefixed with the signature_v2_hdr, either based
 * directly or indirectly on the file data hash.
 *
 * version 2: directly based on the file data hash (e.g. sha*sum)
 *
 * Return: 0 verification good, 1 verification bad, -1 error.
 *
 * (Note: signature_v2_hdr struct does not contain the 'type'.)
 */
static int verify_hash_common(struct public_key_entry *public_keys,
			      const char *file, const char *hash_algo,
			      const unsigned char *hash,
			      int size, unsigned char *sig, int siglen)
{
	int ret = -1;
	EVP_PKEY *pkey, *pkey_free = NULL;
	struct signature_v2_hdr *hdr = (struct signature_v2_hdr *)sig;
	EVP_PKEY_CTX *ctx;
	const EVP_MD *md;
	const char *st;

	pkey = find_keyid(public_keys, hdr->keyid);
	if (!pkey) 
		return -1;

	st = "EVP_PKEY_CTX_new";
	if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
		goto err;
	st = "EVP_PKEY_verify_init";
	if (!EVP_PKEY_verify_init(ctx))
		goto err;
	st = "EVP_get_digestbyname";
	md = EVP_get_digestbyname(hash_algo);
	if (!md)
		goto err;
	st = "EVP_PKEY_CTX_set_signature_md";
	if (!EVP_PKEY_CTX_set_signature_md(ctx, md))
		goto err;
	st = "EVP_PKEY_verify";
	ret = EVP_PKEY_verify(ctx, sig + sizeof(*hdr),
			      siglen - sizeof(*hdr), hash, size);
	if (ret == 1)
		ret = 0;
	else if (ret == 0) {
		log_err("%s: verification failed: %d (%s)\n",
			file, ret, ERR_reason_error_string(ERR_get_error()));
		output_openssl_errors();
		ret = 1;
	}
err:
	if (ret < 0 || ret > 1) {
		log_err("%s: verification failed: %d (%s) in %s\n",
			file, ret, ERR_reason_error_string(ERR_peek_error()),
			st);
		output_openssl_errors();
		ret = -1;
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey_free);
	return ret;
}

/*
 * Verify a signature, prefixed with the signature_v2_hdr, directly based
 * on the file data hash.
 *
 * Return: 0 verification good, 1 verification bad, -1 error.
 */
static int verify_hash_v2(struct public_key_entry *public_keys,
			  const char *file, const char *hash_algo,
			  const unsigned char *hash,
			  int size, unsigned char *sig, int siglen)
{
	/* note: signature_v2_hdr does not contain 'type', use sig + 1 */
	return verify_hash_common(public_keys, file, hash_algo, hash, size,
				  sig + 1, siglen - 1);
}




int imaevm_get_hash_algo(const char *algo)
{
	int i;

	/* first iterate over builtin algorithms */
	for (i = 0; i < PKEY_HASH__LAST; i++)
		if (pkey_hash_algo[i] &&
		    !strcmp(algo, pkey_hash_algo[i]))
			return i;

	return -1;
}

int imaevm_hash_algo_from_sig(unsigned char *sig)
{
	uint8_t hashalgo;

	if (sig[0] == DIGSIG_VERSION_1) {
		hashalgo = ((struct signature_hdr *)sig)->hash;

		if (hashalgo >= DIGEST_ALGO_MAX)
			return -1;

		switch (hashalgo) {
		case DIGEST_ALGO_SHA1:
			return PKEY_HASH_SHA1;
		case DIGEST_ALGO_SHA256:
			return PKEY_HASH_SHA256;
		default:
			return -1;
		}
	} else if (sig[0] == DIGSIG_VERSION_2 || sig[0] == DIGSIG_VERSION_3) {
		hashalgo = ((struct signature_v2_hdr *)sig)->hash_algo;
		if (hashalgo >= PKEY_HASH__LAST)
			return -1;
		return hashalgo;
	} else
		return -1;
}

int imaevm_verify_hash(struct public_key_entry *public_keys, const char *file,
		       const char *hash_algo, const unsigned char *hash,
		       int size, unsigned char *sig, int siglen)
{
	/* Get signature type from sig header */
        if (sig[1] == DIGSIG_VERSION_2)
		return verify_hash_v2(public_keys, file, hash_algo, hash, size,
				      sig, siglen);
	else
		return -1;
}

int verify_hash(const char *file, const unsigned char *hash, int size,
		unsigned char *sig, int siglen)
{
	return imaevm_verify_hash(g_public_keys, file, DEFAULT_HASH_ALGO,
				  hash, size, sig, siglen);
}

int ima_verify_signature2(struct public_key_entry *public_keys, const char *file,
			  unsigned char *sig, int siglen,
			  unsigned char *digest, int digestlen)
{
	unsigned char hash[MAX_DIGEST_SIZE];
	int hashlen, sig_hash_algo;
	const char *hash_algo;

	if (sig[0] != EVM_IMA_XATTR_DIGSIG && sig[0] != IMA_VERITY_DIGSIG) {
		log_err("%s: xattr ima has no signature\n", file);
		return -1;
	}

	if (!digest && sig[0] == IMA_VERITY_DIGSIG) {
		log_err("%s: calculating the fs-verity digest is not supported\n", file);
		return -1;
	}

	sig_hash_algo = imaevm_hash_algo_from_sig(sig + 1);
	if (sig_hash_algo < 0) {
		log_err("%s: Invalid signature\n", file);
		return -1;
	}
	/* Use hash algorithm as retrieved from signature */
	hash_algo = imaevm_hash_algo_by_id(sig_hash_algo);

	/*
	 * Validate the signature based on the digest included in the
	 * measurement list, not by calculating the local file digest.
	 */
	if (digest && digestlen > 0)
		return imaevm_verify_hash(public_keys, file,
					  hash_algo, digest, digestlen,
					  sig, siglen);

	hashlen = ima_calc_hash2(file, hash_algo, hash);
	if (hashlen <= 1)
		return hashlen;
	assert(hashlen <= sizeof(hash));

	return imaevm_verify_hash(public_keys, file, hash_algo, hash, hashlen,
				  sig, siglen);
}

int ima_verify_signature(const char *file, unsigned char *sig, int siglen,
			 unsigned char *digest, int digestlen)
{
	return ima_verify_signature2(g_public_keys, file, sig, siglen,
				     digest, digestlen);
}

/*
 * Calculate keyid of the public_key part of EVP_PKEY
 */
void calc_keyid_v2(uint32_t *keyid, char *str, EVP_PKEY *pkey)
{
	X509_PUBKEY *pk = NULL;
	const unsigned char *public_key = NULL;
	int len;

	/* This is more generic than i2d_PublicKey() */
	if (X509_PUBKEY_set(&pk, pkey) &&
	    X509_PUBKEY_get0_param(NULL, &public_key, &len, NULL, pk)) {
		uint8_t sha1[SHA_DIGEST_LENGTH];

		SHA1(public_key, len, sha1);
		/* sha1[12 - 19] is exactly keyid from gpg file */
		memcpy(keyid, sha1 + 16, 4);
	} else
		*keyid = 0;

	sprintf(str, "%x", __be32_to_cpup(keyid));
	X509_PUBKEY_free(pk);
}

/*
 * Extract SKID from x509 in openssl portable way.
 */
static const unsigned char *x509_get_skid(X509 *x, int *len)
{
	const ASN1_OCTET_STRING *skid = X509_get0_subject_key_id(x);
	if(!skid)
	        return NULL;
	if (len)
		*len = ASN1_STRING_length(skid);
	return ASN1_STRING_get0_data(skid);
}

/*
 * read_keyid_from_cert() - Read keyid from SKID from x509 certificate file
 * @keyid_be:	Output 32-bit keyid in network order (BE);
 * @certfile:	Input filename.
 * @try_der:	true:  try to read in DER from if there is no PEM,
 *		       cert is considered mandatory and error will be issued
 *		       if there is no cert;
 *		false: only try to read in PEM form, cert is considered
 *		       optional.
 * Return:	0 on success, -1 on error.
 */
static int read_keyid_from_cert(uint32_t *keyid_be, const char *certfile, int try_der)
{
	X509 *x = NULL;
	FILE *fp;
	const unsigned char *skid;
	int skid_len;

	if (!(fp = fopen(certfile, "r"))) {
		log_err("Cannot open %s: %s\n", certfile, strerror(errno));
		return -1;
	}
	if (!PEM_read_X509(fp, &x, NULL, NULL)) {
		if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE) {
			ERR_clear_error();
			if (try_der) {
				rewind(fp);
				d2i_X509_fp(fp, &x);
			} else {
				/*
				 * Cert is optional and there is just no PEM
				 * header, then issue debug message and stop
				 * trying.
				 */
				log_err("%s: x509 certificate not found\n",
					  certfile);
				fclose(fp);
				return -1;
			}
		}
	}
	fclose(fp);
	if (!x) {
		ERR_print_errors_fp(stderr);
		log_err("read keyid: %s: Error reading x509 certificate\n",
			certfile);
		return -1;
	}

	if (!(skid = x509_get_skid(x, &skid_len))) {
		log_err("read keyid: %s: SKID not found\n", certfile);
		goto err_free;
	}
	if (skid_len < sizeof(*keyid_be)) {
		log_err("read keyid: %s: SKID too short (len %d)\n", certfile,
			skid_len);
		goto err_free;
	}
	memcpy(keyid_be, skid + skid_len - sizeof(*keyid_be), sizeof(*keyid_be));
	//log_err("keyid %04x (from %s)\n", ntohl(*keyid_be), certfile);
	X509_free(x);
	return 0;

err_free:
	X509_free(x);
	return -1;
}

/*
 * imaevm_read_keyid() - Read 32-bit keyid from the cert file
 * @certfile:	File with certificate in PEM or DER form.
 *
 * Try to read keyid from Subject Key Identifier (SKID) of x509 certificate.
 * Autodetect if cert is in PEM (tried first) or DER encoding.
 *
 * Return: 0 on error or 32-bit keyid in host order otherwise.
 */
uint32_t imaevm_read_keyid(const char *certfile)
{
	uint32_t keyid_be = 0;

	read_keyid_from_cert(&keyid_be, certfile, true);
	/* On error keyid_be will not be set, returning 0. */
	return ntohl(keyid_be);
}

static void lib_init()
{
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
			    OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
	ERR_load_crypto_strings();
}
 
/* ima-sig has content: 
 * hashname_len, hashname, filehash, filename_len, filename, sig_len, sig
 */
static void parse_ima_sig(struct ima_sig_content *s, uint8_t *v, int l) {
        uint8_t *hashname, *filehash, *filename, *sig;
        int hashname_len, filehash_len, filename_len, sig_len;
        
        filehash_len = 32; // hardcoded for sha256 FIXME
        hashname_len = *(uint32_t *)v - filehash_len;
        hashname = v + 4;
        
        filehash = (hashname + hashname_len);
        s->filehash = filehash;
        s->filehash_len = filehash_len;
        
        filename_len = *(uint32_t *)(filehash + 32);
        filename = filehash + filehash_len + 4;
        s->filename = filename;
        s->filename_len = filename_len;
        
        sig_len = *(uint32_t *)(filename + filename_len);
        sig = filename + filename_len + 4;
        s->filesig = sig;
        s->filesig_len = sig_len;
        
}

static void display_ima_template(struct tlv *tlv) {
        struct ima_sig_content s;
        
	if (tlv->t == IMA_TEMPLATE_CONTENT_NAME) {
	        char name[256];
	        memset(name, 0, sizeof(name));
	        strncpy(name, (char *)tlv->v, tlv->l);
	        if(verbose)
	                printf("Template name %s ",name);
	} else if (tlv->t == IMA_TEMPLATE_CONTENT_VALUE) {
		parse_ima_sig(&s, tlv->v, tlv->l);
		printf("%s ", s.filename);
		if(verbose){
		        printf("filehash ");
		        hexdump(s.filehash, s.filehash_len);
		        if (s.filesig_len > 0) {
		                printf("filesig ");
		                hexdump(s.filesig, s.filesig_len);
		        }
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
int verify_ima_sig(uint8_t *v, int l) {
        struct ima_sig_content s;
	if (!g_public_keys) {
	        lib_init();
		init_public_keys("./ima_pub_keys");
	}
        parse_ima_sig(&s, v, l);
        if (s.filesig_len == 0)
                return -1;
        return ima_verify_signature(NULL, s.filesig, s.filesig_len, s.filehash, s.filehash_len);
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
		        if ((i = verify_by_rim(r->sha256)) >= 0)
		                r-> verified_rim = i;
		        if (!verify_ima_sig(tmp->v, tmp->l))
		                r->verified_imasig = 1;
		}
		pos += tmp->l + 5;
	}
}

