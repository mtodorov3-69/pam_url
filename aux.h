/*
 * GNU Copyleft Mirsad Goran Todorovac 2022
 *
 */

#ifndef __AUX_H
#define __AUX_H

#define SAFE_FREE(STR) { if ((STR) != NULL) { explicit_bzero ((STR), strlen (STR)); free (STR); (STR) = NULL; } }
#define FORGET(STR) { if ((STR) != NULL) { explicit_bzero ((STR), strlen (STR)); free (STR); (STR) = NULL; } }
#define FORGET_NOT_FREE(STR) { if ((STR) != NULL) { explicit_bzero ((void *)(STR), strlen (STR)); } }

#define SHA256_STRLEN (SHA256_DIGEST_LENGTH * 2)
#define SHA384_STRLEN (SHA384_DIGEST_LENGTH * 2)
#define SHA512_STRLEN (SHA512_DIGEST_LENGTH * 2)

#include <stdbool.h>

extern bool compromised;
extern int  aux_errno;
extern const char *aux_strerror();

enum aux_errno_t {
	AUX_OK,
	AUX_COMPROMISED_SECRET,
	AUX_WEAK_SECRET,
	AUX_COMPROMISED_NONCE,
	AUX_COMPROMISED_SERIAL,
	AUX_WRITABLE_CONFIG
};

extern char * file_get_contents (const char * const filename);
extern char * file_get_secret (const char * const filename);
bool	      is_sufficiently_complex (const char * const password);
extern char * file_get_contents_trimmed (const char * const filename);
mode_t	      fileperms (const char * const filename);
extern char * trim (const char * const src);
extern char *bin2hex (const unsigned char * const src, int len);
extern char * xor_strings (const char * const s1, const char * const s2, int len);
extern char * xor_strings3 (const char * const s1, const char * const s2, const char * const s3, int len);
extern char * xor_strings3_hex (const char * const s1, const char * const s2, const char * const s3);
extern char *str_concat2 (const char * const s1, const char * const s2);
extern char *str_concat3 (const char * const s1, const char * const s2, const char * const s3);
extern char *str_concat4 (const char * const s1, const char * const s2, const char * const s3, const char * const s4);
extern char *str_concat5 (const char * const s1, const char * const s2, const char * const s3, const char * const s4, const char * const s5);
extern char *my_str_concat2 (const char * const s1, const char * const s2);
extern char *my_str_concat3 (const char * const s1, const char * const s2, const char * const s3);
extern char *my_str_concat4 (const char * const s1, const char * const s2, const char * const s3, const char * const s4);
extern char *my_str_concat5 (const char * const s1, const char * const s2, const char * const s3, const char * const s4, const char * const s5);
extern char *old_str_concat2 (const char * const s1, const char * const s2);
extern char *old_str_concat3 (const char * const s1, const char * const s2, const char * const s3);
extern char *old_str_concat4 (const char * const s1, const char * const s2, const char * const s3, const char * const s4);
extern char *old_str_concat5 (const char * const s1, const char * const s2, const char * const s3, const char * const s4, const char * const s5);

extern bool isspace_str (const char * const src);
extern char * get_unique_nonce (void);
extern char * get_serial (void);
extern char * get_nonce_ctr (void);
extern char * do_get_serial (const char * const serial_file, const char * const lock_file);

#include <openssl/sha.h>

extern char * hashsum (const char * const alg, const char * const strvalue);
extern char * hashsum_file (const char * const alg, const char * const filename);
extern char * hashsum_fmt (const char * const alg, const char * const fmt, ...);
extern bool is_legal_hashalg (const char * const alg);

#endif

