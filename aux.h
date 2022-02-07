/*
 * GNU Copyleft Mirsad Goran Todorovac 2022
 *
 */

#ifndef __AUX_H
#define __AUX_H

#define SAFE_FREE(STR) { if ((STR) != NULL) { explicit_bzero ((STR), strlen (STR)); free (STR); (STR) = NULL; } }

extern char * file_get_contents (const char * const filename);
extern char * trim (const char * const src);
extern bool isspace_str (const char * const src);
extern char * get_random_string (void);
extern char * get_serial (void);
extern char * get_nonce_ctr (void);
extern char * do_get_serial (const char * const serial_file, const char * const lock_file);

#include <openssl/sha.h>

extern char * sha256_string(char *strvalue);
extern void sha256_hash_string (char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]);
extern void sha256(char *string, char outputBuffer[65]);
extern int sha256_file(char *path, char outputBuffer[65]);

#endif

