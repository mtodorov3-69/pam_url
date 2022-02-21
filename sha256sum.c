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

void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[SHA256_STRLEN+1])
{
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }

    outputBuffer[SHA256_STRLEN] = 0;
}

void sha384_hash_string (unsigned char hash[SHA384_DIGEST_LENGTH], char outputBuffer[SHA384_STRLEN+1])
{
    int i = 0;

    for(i = 0; i < SHA384_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }

    outputBuffer[SHA384_STRLEN] = 0;
}

void sha512_hash_string (unsigned char hash[SHA512_DIGEST_LENGTH], char outputBuffer[SHA512_STRLEN+1])
{
    int i = 0;

    for(i = 0; i < SHA512_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }

    outputBuffer[SHA512_STRLEN] = 0;
}

void sha256(char *string, char outputBuffer[SHA256_STRLEN+1])
{
    unsigned char  hash[SHA256_DIGEST_LENGTH];
    int len;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

	len=strlen(string);
    SHA256_Update(&sha256, string,len);
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }
    outputBuffer[SHA256_STRLEN] = 0;
}

char * sha256_string(const char * const strvalue)
{
    char *outputBuffer = malloc (SHA256_STRLEN+1);
    if (outputBuffer == NULL)
	return NULL;

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char *)strvalue, strlen(strvalue), hash);
    sha256_hash_string(hash, outputBuffer);
    return outputBuffer;
}

char * sha384_string(const char * const strvalue)
{
    char *outputBuffer = malloc (SHA384_STRLEN+1);
    if (outputBuffer == NULL)
	return NULL;

    unsigned char hash[SHA384_DIGEST_LENGTH];

    SHA384((const unsigned char *)strvalue, strlen(strvalue), hash);
    sha384_hash_string(hash, outputBuffer);
    return outputBuffer;
}

char * sha512_string(const char * const strvalue)
{
    char *outputBuffer = malloc (SHA512_STRLEN+1);
    if (outputBuffer == NULL)
	return NULL;

    unsigned char hash[SHA512_DIGEST_LENGTH];

    SHA512((const unsigned char *)strvalue, strlen(strvalue), hash);
    sha512_hash_string(hash, outputBuffer);
    return outputBuffer;
}

/*
 * mtodorov, 2022-02-08
 * asprintf-like function with fmt to concat strings and calculate sha256sum
 *
 */

char * sha256sum_fmt (const char * const fmt, ...)
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
	fprintf (stderr, "hashsum_fmt: val='%s'\n", buf);
	return sha256_string (buf);
}

char * sha384sum_fmt (const char * const fmt, ...)
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
	return sha384_string (buf);
}

char * sha512sum_fmt (const char * const fmt, ...)
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
	return sha512_string (buf);
}

//perform the SHA3-256 hash
char * sha3_256(const char * const input)
{
    uint32_t digest_length = SHA256_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_256();
    uint8_t* digest = (uint8_t *) (OPENSSL_malloc(digest_length));
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, NULL);
    EVP_DigestUpdate(context, input, strlen (input));
    EVP_DigestFinal_ex(context, digest, &digest_length);
    EVP_MD_CTX_destroy(context);
    char * output = bin2hex(digest, digest_length);
    OPENSSL_free(digest);
    return output;
}

//perform the SHA3-384 hash
char * sha3_384(const char * const input)
{
    uint32_t digest_length = SHA384_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_384();
    uint8_t* digest = (uint8_t *) (OPENSSL_malloc(digest_length));
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, NULL);
    EVP_DigestUpdate(context, input, strlen (input));
    EVP_DigestFinal_ex(context, digest, &digest_length);
    EVP_MD_CTX_destroy(context);
    char * output = bin2hex(digest, digest_length);
    OPENSSL_free(digest);
    return output;
}

//perform the SHA3-512 hash
char * sha3_512(const char * const input)
{
    uint32_t digest_length = SHA512_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_512();
    uint8_t* digest = (uint8_t *) (OPENSSL_malloc(digest_length));
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, NULL);
    EVP_DigestUpdate(context, input, strlen (input));
    EVP_DigestFinal_ex(context, digest, &digest_length);
    EVP_MD_CTX_destroy(context);
    char * output = bin2hex(digest, digest_length);
    OPENSSL_free(digest);
    return output;
}

//perform the RIPEMD160 hash
char * ripemd160(const char * const input)
{
    uint32_t digest_length = RIPEMD160_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_ripemd160();
    uint8_t* digest = (uint8_t *) (OPENSSL_malloc(digest_length));
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, NULL);
    EVP_DigestUpdate(context, input, strlen (input));
    EVP_DigestFinal_ex(context, digest, &digest_length);
    EVP_MD_CTX_destroy(context);
    char * output = bin2hex(digest, digest_length);
    OPENSSL_free(digest);
    return output;
}

/* mtodorov 2022-02-20
   - minimum implementation of Swiss knife pluggable hash functions v0.1
*/

#define UNKNOWN_ALGORITHM (-1)

struct hashalg {
    const char              *algname;
    const EVP_MD * 	   (*algorithm) (void);
    uint32_t      	     digest_length;
};

struct hashalg algorithm_tbl [] =
{
#ifdef ALLOW_INSECURE_ALGORITHMS
{	"sha1",		EVP_sha1,	SHA_DIGEST_LENGTH	},
#endif
{	"sha224",	EVP_sha224,	SHA224_DIGEST_LENGTH	},
{	"sha256",	EVP_sha256,	SHA256_DIGEST_LENGTH	},
{	"sha384",	EVP_sha384,	SHA384_DIGEST_LENGTH	},
{	"sha512",	EVP_sha512,	SHA512_DIGEST_LENGTH	},
{	"sha3-224",	EVP_sha3_224,	SHA224_DIGEST_LENGTH	},
{	"sha3-256",	EVP_sha3_256,	SHA256_DIGEST_LENGTH	},
{	"sha3-384",	EVP_sha3_384,	SHA384_DIGEST_LENGTH	},
{	"sha3-512",	EVP_sha3_512,	SHA512_DIGEST_LENGTH	},
{	"ripemd160",	EVP_ripemd160,	RIPEMD160_DIGEST_LENGTH	},
{	"whirlpool",	EVP_whirlpool,	WHIRLPOOL_DIGEST_LENGTH	},
#ifdef USE_HASH_SM3
{	"sm3",		EVP_sm3,	256/8			},
#endif
{	NULL,		NULL,		0			}
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
    uint32_t digest_length  = algorithm_tbl [alg_index].digest_length;
    const EVP_MD* algorithm = (algorithm_tbl [alg_index].algorithm)();
    uint8_t* digest = (uint8_t *) (OPENSSL_malloc(digest_length));
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

int sha256_file(char *path, char outputBuffer[SHA256_STRLEN+1])
{
    FILE *file = fopen(path, "rb");
    if(!file) return -534;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return ENOMEM;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, outputBuffer);
    fclose(file);
    free(buffer);
    return 0;
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
*/
	if (argv[1]) {
		printf("%s %s sha3-256\n", sha3_256(argv[1]), hashsum ("sha3-256", argv[1]));
		printf("%s %s sha3-384\n", sha3_384(argv[1]), hashsum ("sha3-384", argv[1]));
		printf("%s %s sha3-512\n", sha3_512(argv[1]), hashsum ("sha3-512", argv[1]));
	} else
		printf("Usage: %s string\n", argv[0]);

	return 0;
}

#endif

