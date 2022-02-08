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
#include <openssl/sha.h>
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
	return sha256_string (buf);
}

char * hashsum (const char * const alg, const char * const str)
{
	     if (strcmp (alg, "sha256") == 0)
		return sha256_string (str);
	else if (strcmp (alg, "sha384") == 0)
		return sha384_string (str);
	else if (strcmp (alg, "sha512") == 0)
		return sha512_string (str);
	else {
		fprintf (stderr, "%s: Unknown encryption algorythm.\n", alg);
		exit (7);
	}
}

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

	for (int i = 0; i < 10000; i++) {
		char *s1 = get_random_string ();
		char *s2 = get_random_string ();
		char *s3 = get_random_string ();
		char *s4 = get_random_string ();
		char *buf = NULL, *hash1 = NULL, *hash2 = NULL;
		asprintf (&buf, "%s%s%s%s", s1, s2, s3, s4);
		hash1 = sha256_string (buf);
		free (buf);
		if (strcmp (hash1, hash2 = hashsum_fmt ("sha256", "%s%s%s%s", s1, s2, s3, s4)) != 0)
			printf("hash1 = '%s', hash2 = '%s'\n", hash1, hash2);
	}

	for (int i = 0; i < 10000; i++) {
		char *s1 = get_random_string ();
		char *s2 = get_random_string ();
		char *s3 = get_random_string ();
		char *s4 = get_random_string ();
		char *buf = NULL, *hash1 = NULL, *hash2 = NULL;
		asprintf (&buf, "%s%s%s%s", s1, s2, s3, s4);
		hash1 = sha384_string (buf);
		free (buf);
		if (strcmp (hash1, hash2 = hashsum_fmt ("sha384", "%s%s%s%s", s1, s2, s3, s4)) != 0)
			printf("hash1 = '%s', hash2 = '%s'\n", hash1, hash2);
	}

	for (int i = 0; i < 10000; i++) {
		char *s1 = get_random_string ();
		char *s2 = get_random_string ();
		char *s3 = get_random_string ();
		char *s4 = get_random_string ();
		char *buf = NULL, *hash1 = NULL, *hash2 = NULL;
		asprintf (&buf, "%s%s%s%s", s1, s2, s3, s4);
		hash1 = sha512_string (buf);
		free (buf);
		if (strcmp (hash1, hash2 = hashsum_fmt ("sha512", "%s%s%s%s", s1, s2, s3, s4)) != 0)
			printf("hash1 = '%s', hash2 = '%s'\n", hash1, hash2);
	}

	// printf("%s\n", sha256_string(argv[1]));
	return 0;
}

#endif

