/*
 * GNU Copyleft Mirsad Goran Todorovac 2022
 *
 */

#ifndef __AUX_H
#define __AUX_H

#define SAFE_FREE(STR) { if ((STR) != NULL) { explicit_bzero ((STR), strlen (STR)); free (STR); (STR) = NULL; } }

#define SHA256_STRLEN (SHA256_DIGEST_LENGTH * 2)
#define SHA384_STRLEN (SHA384_DIGEST_LENGTH * 2)
#define SHA512_STRLEN (SHA512_DIGEST_LENGTH * 2)

#include <stdbool.h>

extern char * file_get_contents (const char * const filename);
extern char * trim (const char * const src);
extern char * xor_strings (const char * const s1, const char * const s2, int len);
extern char * xor_strings3 (const char * const s1, const char * const s2, const char * const s3, int len);
extern bool isspace_str (const char * const src);
extern char * get_random_string (void);
extern char * get_serial (void);
extern char * get_nonce_ctr (void);
extern char * do_get_serial (const char * const serial_file, const char * const lock_file);

#include <openssl/sha.h>

extern char * sha256_string(const char * const strvalue);
extern char * sha256sum_fmt (const char * const fmt, ...);
extern char * sha384_string(const char * const strvalue);
extern char * sha384sum_fmt (const char * const fmt, ...);
extern char * sha512_string(const char * const strvalue);
extern char * sha512sum_fmt (const char * const fmt, ...);
extern char * hashsum (const char * const alg, const char * const strvalue);
extern char * hashsum_fmt (const char * const alg, const char * const fmt, ...);
extern void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]);
extern void sha256(char *string, char outputBuffer[65]);
extern int sha256_file(char *path, char outputBuffer[65]);

#endif


