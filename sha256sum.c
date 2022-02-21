/*
 * Source based on example from Keith Hedger, www.linuxquestions.org.
 *
 * Modified by Mirsad Goran Todorovac 2022-02-06
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/whrlpool.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include "aux.h"

#define SHA256_STRLEN (SHA256_DIGEST_LENGTH * 2)
// #define SHA256_STRLEN 64

#define USE_HASH_SM3 1

/* mtodorov 2022-02-20
   - minimum implementation of Swiss knife pluggable hash functions v0.1
*/

#define UNKNOWN_ALGORITHM (-1)

struct hash_alg {
    const char              *algname;
    const EVP_MD * 	   (*algorithm) (void);
};

struct hash_alg algorithm_tbl [] =
{
#ifdef ALLOW_INSECURE_ALGORITHMS
{	"md5",		EVP_md5		},
{	"sha1",		EVP_sha1	},
#endif
{	"sha224",	EVP_sha224	},
{	"sha256",	EVP_sha256	},
{	"sha384",	EVP_sha384	},
{	"sha512",	EVP_sha512	},
{	"sha3-224",	EVP_sha3_224	},
{	"sha3-256",	EVP_sha3_256	},
{	"sha3-384",	EVP_sha3_384	},
{	"sha3-512",	EVP_sha3_512	},
{	"ripemd160",	EVP_ripemd160	},
{	"whirlpool",	EVP_whirlpool	},
{	"blake2s256",	EVP_blake2s256	},
{	"blake2b512",	EVP_blake2b512	},
#ifdef USE_HASH_SM3
{	"sm3",		EVP_sm3		},
#endif
{	NULL,		NULL		}
};

int get_hashalg_index (const char * const alg)
{
	for (int i = 0; algorithm_tbl[i].algname != NULL; i++)
		if (strcmp (algorithm_tbl[i].algname, alg) == 0)
			return i;

	return UNKNOWN_ALGORITHM;
}

//perform the Swiss knife hash
char * hashsum(const char * const alg, const char * const input)
{
    int alg_index = get_hashalg_index (alg);
    if (alg_index == UNKNOWN_ALGORITHM)
	return NULL;
    const EVP_MD* algorithm = (algorithm_tbl [alg_index].algorithm)();
    uint32_t digest_length  = EVP_MD_size (algorithm); // FIXME: find this struct def include!!!
    uint8_t* digest = (uint8_t *) (OPENSSL_malloc(digest_length));
    // uint32_t digest_length  = algorithm_tbl [alg_index].digest_length;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, NULL);
    EVP_DigestUpdate(context, input, strlen (input));
    EVP_DigestFinal_ex(context, digest, &digest_length);
    EVP_MD_CTX_destroy(context);
    char * output = bin2hex(digest, digest_length);
    OPENSSL_free(digest);
    return output;
}

bool is_legal_hashalg (const char * const alg)
{
	for (int i = 0; algorithm_tbl[i].algname != NULL; i++)
		if (!strcmp (algorithm_tbl[i].algname, alg) == 0)
			return true;

	return false;
}

/*
char * hashsum (const char * const alg, const char * const str)
{
	     if (strcmp (alg, "sha256") == 0)
		return sha256_string (str);
	else if (strcmp (alg, "sha2-256") == 0)
		return sha256_string (str);
	else if (strcmp (alg, "sha384") == 0)
		return sha384_string (str);
	else if (strcmp (alg, "sha2-384") == 0)
		return sha384_string (str);
	else if (strcmp (alg, "sha512") == 0)
		return sha512_string (str);
	else if (strcmp (alg, "sha2-512") == 0)
		return sha512_string (str);
	else if (strcmp (alg, "sha3-256") == 0)
		return sha3_256 (str);
	else if (strcmp (alg, "sha3-384") == 0)
		return sha3_384 (str);
	else if (strcmp (alg, "sha3-512") == 0)
		return sha3_512 (str);
	else if (strcmp (alg, "ripemd160") == 0)
		return ripemd160 (str);
	else {
		fprintf (stderr, "%s: Unknown encryption algorythm.\n", alg);
		return NULL;
	}
}
*/

char * hashsum_fmt (const char * const alg, const char * const fmt, ...)
{
	int ret = 0;
	va_list argp;
	char * buf = NULL;

	va_start (argp, fmt);
	ret = vasprintf (&buf, fmt, argp);
	va_end (argp);

	if (ret == -1) {
		if (buf)
			free (buf);
		return NULL;
	}

	return hashsum (alg, buf);
}

char *sha256_file(const char * const path)
{
    FILE *file = fopen(path, "rb");
    if(!file) return NULL;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return NULL;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    char *retval = bin2hex(hash, SHA256_DIGEST_LENGTH);
    fclose(file);
    free(buffer);
    return retval;
}

#define BUFSIZE 65536

//perform the Swiss knife hash
char * hashsum_file(const char * const alg, const char * const filename)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL)
	return NULL;
    int alg_index = get_hashalg_index (alg);
    if (alg_index == UNKNOWN_ALGORITHM)
	return NULL;
    const EVP_MD* algorithm = (algorithm_tbl [alg_index].algorithm)();
    uint32_t digest_length  = EVP_MD_size (algorithm); // FIXME: find this struct def include!!!
    uint8_t* digest = (uint8_t *) (OPENSSL_malloc(digest_length));
    unsigned char *buffer = malloc(BUFSIZE);
    if (buffer == NULL)
	return NULL;
    int rd = 0;
    // uint32_t digest_length  = algorithm_tbl [alg_index].digest_length;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, NULL);
    while ((rd = fread (buffer, 1, BUFSIZE, fp)))
    {
        EVP_DigestUpdate(context, buffer, rd);
    }
    EVP_DigestFinal_ex(context, digest, &digest_length);
    EVP_MD_CTX_destroy(context);
    char * output = bin2hex(digest, digest_length);
    free (buffer);
    OPENSSL_free(digest);
    return output;
}

#ifdef MAIN_SHA256

int main(int argc, char **argv)
{
	char calc_hash[SHA256_STRLEN+1];
/*
	for (int i = 0; i < 10000; i++) {
		char *s1, *s2, *s3, *s4;
		char *buf = NULL, *hash1 = NULL, *hash2 = NULL;
		s1 = get_random_string ();
		s2 = get_random_string ();
		s3 = get_random_string ();
		s4 = get_random_string ();
		buf = NULL, hash1 = NULL, hash2 = NULL;
		asprintf (&buf, "%s%s%s%s", s1, s2, s3, s4);
		hash1 = sha256_string (buf);
		free (buf);
		if (strcmp (hash1, hash2 = hashsum_fmt ("sha256", "%s%s%s%s", s1, s2, s3, s4)) != 0)
			printf("hash1 = '%s', hash2 = '%s'\n", hash1, hash2);
	}

	for (int i = 0; i < 10000; i++) {
		char *s1, *s2, *s3, *s4;
		char *buf = NULL, *hash1 = NULL, *hash2 = NULL;
		s1 = get_random_string ();
		s2 = get_random_string ();
		s3 = get_random_string ();
		s4 = get_random_string ();
		asprintf (&buf, "%s%s%s%s", s1, s2, s3, s4);
		hash1 = sha384_string (buf);
		free (buf);
		if (strcmp (hash1, hash2 = hashsum_fmt ("sha384", "%s%s%s%s", s1, s2, s3, s4)) != 0)
			printf("hash1 = '%s', hash2 = '%s'\n", hash1, hash2);
	}

	for (int i = 0; i < 10000; i++) {
		char *s1, *s2, *s3, *s4;
		char *buf = NULL, *hash1 = NULL, *hash2 = NULL;
		s1 = get_random_string ();
		s2 = get_random_string ();
		s3 = get_random_string ();
		s4 = get_random_string ();
		asprintf (&buf, "%s%s%s%s", s1, s2, s3, s4);
		hash1 = sha512_string (buf);
		free (buf);
		if (strcmp (hash1, hash2 = hashsum_fmt ("sha512", "%s%s%s%s", s1, s2, s3, s4)) != 0)
			printf("hash1 = '%s', hash2 = '%s'\n", hash1, hash2);
	}
	if (argv[1]) {
		printf("%s %s sha3-256\n", sha3_256(argv[1]), hashsum ("sha3-256", argv[1]));
		printf("%s %s sha3-384\n", sha3_384(argv[1]), hashsum ("sha3-384", argv[1]));
		printf("%s %s sha3-512\n", sha3_512(argv[1]), hashsum ("sha3-512", argv[1]));
	} else
		printf("Usage: %s string\n", argv[0]);

	return 0;
*/

	if (argc != 3) {
		fprintf(stderr, "Usage: %s alg file\n", argv[0]);
		exit (1);
	}

	printf ("%s\t%s\n", argv[2], hashsum_file (argv[1], argv[2]));

}

#endif

