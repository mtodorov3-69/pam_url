/*
 * Mirsad Goran Todorovac 2022 GNU Copyleft.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/syscall.h>

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif

#define gettid() ((pid_t)syscall(SYS_gettid))

#include "aux.h"

#define SERIAL_FILE "/var/lib/pam_url/serial"
#define LOCK_FILE "/var/lib/pam_url/serial.lock"
#define NONCE_CTR_FILE "/var/lib/pam_url/nonce_ctr"
#define NONCE_CTR_LOCK_FILE "/var/lib/pam_url/nonce_ctr.lock"
#define SERIAL_FILE "/var/lib/pam_url/serial"
#define SERIAL_INITVAL 1
#define BUFSIZE 4096

bool compromised = false;
int  aux_errno   = AUX_OK;

#ifdef DEBUG
bool get_serial_debug = true;
#else
bool get_serial_debug = false;
#endif

/* char * get_serial (void)
	mtodorov 2022-Feb-18 v0.02.02 refuse to authenticate with compromised auth
	mtodorov 2022-Feb-07 v0.02.01 hardening get_random_string()
	mtodorov 2022-Feb-07 v0.02.00 implemented nonce counter (RFC 5116)
	mtodorov 2022-Feb-07 v0.01.02 open serial_file if it doesn't exist
	mtodorov 2022-Feb-07 v0.01.01 fixed a bug with read into &buf.
	mtodorov 2022-Feb-07 v0.01.00
*/

char * do_get_serial (const char * const serial_file, const char * const lock_file)
{
	struct stat stat_buf;
	int fd, lock_fd;
	char *buf = NULL;
	long long serial = 0;
	int wr = 0;
	char *strbuf = NULL;

	if ((lock_fd = open (lock_file, O_RDWR | O_CREAT | O_EXCL, S_IRUSR)) == -1)
		goto getserial_fail;

	if ((fd = open (serial_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) == -1)
		goto getserial_fail_unlinklock;

	if (fstat (fd, &stat_buf) == -1)
		goto getserial_fail_closefd;

        /* eliminating the possibility of a race condition with loose perms */
        if (stat_buf.st_uid != 0 || (stat_buf.st_mode & (S_IRWXG | S_IRWXO)))
	{
		compromised = true;
		goto getserial_fail_closefd;
	}

	if ((buf = (char *) calloc (1, stat_buf.st_size + 1)) == NULL)
		goto getserial_fail_closefd;

	if ((read (fd, buf, stat_buf.st_size) == -1))
		if (get_serial_debug)
			fprintf (stderr, "%s: unable to read: %s\n", serial_file, strerror (errno));

	if (isspace_str (buf))
		serial = SERIAL_INITVAL;
	else {
		serial = strtoll (buf, NULL, 0);
		if (errno == ERANGE) {
			fprintf (stderr, "%s: counter overlapped: %s\n", serial_file, strerror (errno));
			serial = SERIAL_INITVAL;
		} else
			serial ++;
	}

	if ((lseek (fd, 0, SEEK_SET) == -1) || (ftruncate (fd, 0) == -1))
		goto getserial_fail_freebuf;

	if (asprintf (&strbuf, "%lld", serial) == -1 || strbuf == NULL)
		goto getserial_fail_freestrbuf;

	if ((wr = write (fd, strbuf, strlen (strbuf))) == -1 || wr != strlen (strbuf))
		goto getserial_fail_freestrbuf;

	if (fsync (fd) == -1)
		goto getserial_fail_freestrbuf;

	if (get_serial_debug)
		fprintf (stderr, "serial = %s\n", strbuf);

	// here we duplicate some code, but it gives serenity:
	if (buf != NULL)
		free (buf);
	if (close (fd) == -1)
		fprintf (stderr, "Could not close '%s': %s.\n", serial_file, strerror (errno));
	if (close (lock_fd) == -1)
		fprintf (stderr, "Could not close '%s': %s.\n", lock_file, strerror (errno));
	if (unlink (lock_file) == -1)
		fprintf (stderr, "Could not unlink '%s': %s.\n", lock_file, strerror (errno));
	return strbuf;

getserial_fail_freestrbuf:
	if (strbuf)
		free (strbuf);
getserial_fail_freebuf:
	if (buf)
		free (buf);
getserial_fail_closefd:
	if (close (fd) == -1)
		fprintf (stderr, "Could not close '%s': %s.\n", serial_file, strerror (errno));
getserial_fail_unlinklock:
	if (close (lock_fd) == -1)
		fprintf (stderr, "Could not close '%s': %s.\n", lock_file, strerror (errno));
	if (unlink (LOCK_FILE) == -1)
		fprintf (stderr, "Could not unlink '%s': %s.\n", lock_file, strerror (errno));
getserial_fail:
	return NULL;
}

char * get_serial (void)
{
	char *serial = do_get_serial (SERIAL_FILE, LOCK_FILE);
	
	if (compromised)
		aux_errno = AUX_COMPROMISED_SERIAL;

	return serial;
}

char * get_nonce_ctr (void)
{
	char * nonce = do_get_serial (NONCE_CTR_FILE, NONCE_CTR_LOCK_FILE);

	if (compromised)
		aux_errno = AUX_COMPROMISED_NONCE;

	return nonce;
}

#define MAXHOSTBUF ((MAXHOSTNAMELEN>1024)?MAXHOSTNAMELEN:1024)
#define MACHINEID "/etc/machine-id"
// #define USE_DNS 1
#define USE_DEV_URANDOM 1

pthread_mutex_t nonce_lock;

char *get_unique_nonce (void)
{
	static bool _first_run = true;
	static struct drand48_data buffer1, buffer2, buffer3;
	double result1, result2, result3;
	struct timespec tv1, tv2, tv3, tv4, tv5;
	char * retval = NULL;
	char *nonce_ctr = get_nonce_ctr();
	char hostname[MAXHOSTBUF+1];
	char *fqdn = NULL, *machineid = NULL;
#ifdef USE_DNS
	struct addrinfo hints, *res = NULL;
#endif
#ifdef USE_DEV_URANDOM
	int fd;
#endif
	unsigned long rnd = 0;

	if (nonce_ctr == NULL)
		goto get_random_exit2;

	if (clock_gettime (CLOCK_MONOTONIC, &tv1) == -1)
		goto get_random_exit;

	if (clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &tv2) == -1)
		goto get_random_exit;

	if (clock_gettime (CLOCK_THREAD_CPUTIME_ID, &tv3) == -1)
		goto get_random_exit;

	if (clock_gettime (CLOCK_MONOTONIC_RAW, &tv4) == -1)
		goto get_random_exit;

	if (clock_gettime (CLOCK_BOOTTIME, &tv5) == -1)
		goto get_random_exit;

#ifdef USE_DEV_URANDOM
	/* RFC 4086 chapter 7.1.2 compliant */
	if ((fd = open ("/dev/urandom", O_RDONLY)) == -1)
		goto get_random_exit;

	if (read (fd, &rnd, sizeof (rnd)) != sizeof (rnd))
		goto get_random_exit;

	if (close (fd) == -1)
		goto get_random_exit;
#endif

	/* Addressing RFC 5116, chapter 8, paragraph 4 concerns:

	   It is very difficult for an attacker who would use VM rollback which would
	   rewind the nounce counter on hard drive to set all three time counters and
	   only one nanosecond difference in any of them is sufficient to generate
	   a unique nonce.
	   If all the timers happen to be the same still called by different threads
	   simultanously on different cores, they will have different thread ID.
	   If the system has coarse time resolution, unlike Linux, in theory it could
	   call the nonce generator with the same value of all three counters and
	   thread ID. However, the nonce counter would be different, and the PRNG
	   would be seeded only the first time.
	   Since the process scheduling is stochastic, it is very low probability
	   that all of the monotonic clock, process clock and thread clock would again
	   be the same, in particular the monotonic clock which is linked to calendar time.
	   The same nanosecond on all three counters won't repeat in UTC clock with rollback.
	   If the attacker could set even the nanosecond monotonic clock, and start
	   the nonce generator at exact time, different process and thread schedulers
	   would never repeat the same as they depend on random physical events. 
	   Theoretically an attacker could rollback the VM and set all three counters,
	   but only if he is already in control of the kernel, which makes all
	   security compromised.
	   This implementation SHOULD protect against ACCIDENTAL repeating of the nonce
	   by rolling back VM and nonce counter.
	*/

	pthread_mutex_lock (&nonce_lock);
	if (_first_run) {
		_first_run = false;
		srand48_r ((tv1.tv_sec << 32 | tv1.tv_nsec) ^ (tv2.tv_sec << 32 | tv2.tv_nsec) ^
			   (tv3.tv_sec << 32 | tv3.tv_nsec), &buffer1);
		srand48_r ((tv3.tv_sec << 32 | tv3.tv_nsec) ^ (tv4.tv_sec << 32 | tv2.tv_nsec) ^
			   (tv5.tv_sec << 32 | tv5.tv_nsec), &buffer2);
		srand48_r ( rnd ^ getpid() ^ gettid(), &buffer3);
	}
	pthread_mutex_unlock (&nonce_lock);
	drand48_r (&buffer1, &result1);
	drand48_r (&buffer2, &result2);
	drand48_r (&buffer2, &result3);

	if (gethostname (hostname, sizeof (hostname)) == -1)
		goto get_random_exit;

	hostname[MAXHOSTBUF] = '\0';
	fqdn = hostname;

#ifdef USE_DNS
	/* DNS is insecure, but we do not depend on it as machineid is
	   sufficient for uniqueness and RFC 5116 compliance. */
	if (strstr (hostname, ".") == NULL)
	{
		bzero (&hints, sizeof (hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags  = AI_CANONNAME;
		if (getaddrinfo (hostname, NULL, &hints, &res) == 0)
		{
			fqdn = res->ai_canonname;
		}
		else
			fprintf (stderr, "getaddrinfo: %s\n", strerror (errno));
	}
#endif

	//printf ("fqdn='%s'\n", fqdn);

	if (fqdn == NULL)
		goto get_random_exit;

	if ((machineid = file_get_contents_trimmed (MACHINEID)) == NULL)
		goto get_random_exit;

	//printf ("machineid='%s'\n", machineid);

	retval = hashsum_fmt ("sha3-256", "%s:%s:%lf:%ld:%ld:%ld:%ld:%ld:%ld:%ld:%ld:%d:%ld:%ld%lf:%lf:%lu:%s",
				fqdn, machineid,
				result1,
				tv1.tv_sec, tv1.tv_nsec, tv2.tv_sec, tv2.tv_nsec,
				tv3.tv_sec, tv3.tv_nsec, tv4.tv_sec, tv4.tv_nsec,
				tv5.tv_sec, tv5.tv_nsec,
				getpid(), result2, result3, rnd, nonce_ctr);

	if (get_serial_debug)
		fprintf (stderr, "retval = %s\n", retval);

get_random_exit:
	if (nonce_ctr != NULL)
		free (nonce_ctr);
get_random_exit2:
	return retval;
}

char *trim (const char * const source)
{
	int len = strlen (source);
	int destlen;
	const char *p, *q;

	for (p = source; *p && isspace (*p); p++);
	for (q = source + len - 1; *q && isspace (*q); q--);
	char *trimstr = malloc (destlen = (q - p) + 1);
	// printf ("source='%s' p='%s' q='%s' q-p=%ld destlen=%d\n", source, p, q, q-p, destlen);
	strncpy (trimstr, p, destlen);
	trimstr [destlen] = '\0';
	return trimstr;
}

/*
 * check if src is an empty or n entire whitespace string
 */
bool isspace_str (const char * const src)
{
	const char *p = src;

	for (; *p && isspace (*p); p++);
	if (*p == '\0')
		return true;
	else
		return false;
}

char *xor_strings (const char * const s1, const char * const s2, int len)
{
	const char *p = s1, *q = s2;
	int i = 0;
	char *result = (char *) malloc (len + 1);
	char *r = result;

	if (result != NULL)
	{
		for ( ; *p && *q && i < len; p++, q++, i++) {
			*r = *p ^ *q;
			// fprintf(stderr, "i=%d result[i]='%c' *p='%c' *q='%c'\n", i, *r, *p, *q);
			r ++;
		}

		*r = '\0';
	}
	return result;
}

char *xor_strings3 (const char * const s1, const char * const s2, const char * const s3, int len)
{
	const char *p = s1, *q = s2, *r = s3;
	int i = 0;
	char *result = (char *) malloc (len + 1);
	char *s = result;

	if (result != NULL)
	{
		for ( ; *p && *q && *r && i < len; p++, q++, r++, i++) {
			*s = *p ^ *q ^ *r;
			// fprintf(stderr, "i=%d result[i]='%c' *p='%c' *q='%c' *r='%c'\n", i, result[i], *p, *q, *r);
			s ++;
		}

		*s = '\0';
	}
	return result;
}

char *bin2hex (const unsigned char * const src, int len)
{
	char *retbuf = (char *) malloc (len * 2 + 1);
	char *hex = retbuf;

	if (retbuf == NULL)
		return NULL;

	for (int i = 0; i < len; i++)
	{
		*hex++ = "0123456789abcdef" [src [i] >> 4];
		*hex++ = "0123456789abcdef" [src [i] & 0x0f ];
	}
	*hex = '\0';
	assert (hex - retbuf == len * 2);
	return retbuf;
}

char *xor_strings3_hex (const char * const s1, const char * const s2, const char * const s3)
{
	int len1 = strlen (s1), len2 = strlen (s2), len3 = strlen (s3);
	int len = (len1 < len2) ? ((len1 < len3) ? len1 : len3) : ( (len2 < len3) ? len2 : len3);
	const char *p = s1, *q = s2, *r = s3;
	int i = 0;
	char *result = (char *) malloc (len + 1);
	char *s = result;

	if (result != NULL)
	{
		for ( ; *p && *q && *r && i < len; p++, q++, r++, i++) {
			*s = *p ^ *q ^ *r;
			// fprintf(stderr, "i=%d result[i]='%c' *p='%c' *q='%c' *r='%c'\n", i, result[i], *p, *q, *r);
			s ++;
		}

		*s = '\0';
	}

	assert (s - result == len);

	char *hex_result = bin2hex ((unsigned char *)result, s - result);

	// fprintf (stderr, "size=%d hex_result='%s'\n", s - result, hex_result);

	explicit_bzero (result, len);
	free (result);

	return hex_result;
}

char *my_str_concat2 (const char * const s1, const char * const s2)
{
	if (s1 == NULL || s2 == NULL)
		return NULL;

	int len1 = strlen(s1), len2 = strlen(s2);
	int len = len1 + len2;
	char *retbuf = (char *) malloc (len + 1);

	if (retbuf == NULL)
		return NULL;

	char *s = stpcpy (retbuf, s1);
	s = stpcpy (s, s2);

	assert (s - retbuf == len);

	if (strcmp (retbuf, s = str_concat2 (s1, s2)) != 0)
		fprintf (stderr, "s1='%s'\ns2='%s'\n", retbuf, s);

	return retbuf;
}

char *my_str_concat3 (const char * const s1, const char * const s2, const char * const s3)
{
	if (s1 == NULL || s2 == NULL || s3 == NULL)
		return NULL;

	fprintf (stderr, "s1='%s', s2='%s', s3='%s'\n", s1, s2, s3);
	int len1 = strlen(s1), len2 = strlen(s2), len3 = strlen(s3);
	int len = len1 + len2 + len3;
	char *retbuf = (char *) malloc (len + 1);
	fprintf (stderr, "len1=%d, len2=%d, len3=%d\n", len1, len2, len3);

	if (retbuf == NULL)
		return NULL;

	char *s = stpncpy (retbuf, s1, len1);
	s = stpncpy (s, s2, len2);
	s = stpncpy (s, s3, len3);

	assert (s - retbuf == len);

	if (strcmp (retbuf, s = str_concat3 (s1, s2, s3)) != 0)
		fprintf (stderr, "s1='%s'\ns2='%s'\n", retbuf, s);

	return retbuf;
}

char *my_str_concat4 (const char * const s1, const char * const s2, const char * const s3, const char * const s4)
{
	if (s1 == NULL || s2 == NULL || s3 == NULL || s4 == NULL)
		return NULL;

	int len1 = strlen(s1), len2 = strlen(s2), len3 = strlen(s3), len4 = strlen(s4);
	int len = len1 + len2 + len3 + len4;
	char *retbuf = (char *) malloc (len + 1);

	if (retbuf == NULL)
		return NULL;

	char *s = stpcpy (retbuf, s1);
	s = stpcpy (s, s2);
	s = stpcpy (s, s3);
	s = stpcpy (s, s4);

	assert (s - retbuf == len);

	if (strcmp (retbuf, s = str_concat4 (s1, s2, s3, s4)) != 0)
		fprintf (stderr, "s1='%s'\ns2='%s'\n", retbuf, s);

	return retbuf;
}

char *my_str_concat5 (const char * const s1, const char * const s2, const char * const s3, const char * const s4, const char * const s5)
{
	if (s1 == NULL || s2 == NULL || s3 == NULL || s4 == NULL || s5 == NULL)
		return NULL;

	int len1 = strlen(s1), len2 = strlen(s2), len3 = strlen(s3), len4 = strlen(s4), len5 = strlen(s5);
	int len = len1 + len2 + len3 + len4 + len5;
	char *retbuf = (char *) malloc (len + 1);

	if (retbuf == NULL)
		return NULL;

	char *s = stpcpy (retbuf, s1);
	s = stpcpy (s, s2);
	s = stpcpy (s, s3);
	s = stpcpy (s, s4);
	s = stpcpy (s, s5);

	assert (s - retbuf == len);

	if (strcmp (retbuf, s = str_concat5 (s1, s2, s3, s4, s5)) != 0)
		fprintf (stderr, "s1='%s' s2='%s'\n", retbuf, s);

	return retbuf;
}

char *str_concat2 (const char * const s1, const char * const s2)
{
	char *retbuf = NULL;

	if (asprintf(&retbuf, "%s%s", s1, s2) == -1)
	{
		if (retbuf != NULL)
			SAFE_FREE (retbuf);
		return NULL;
	}
	return retbuf;
}

char *str_concat3 (const char * const s1, const char * const s2, const char * const s3)
{
	char *retbuf = NULL;

	if (asprintf(&retbuf, "%s%s%s", s1, s2, s3) == -1)
	{
		if (retbuf != NULL)
			SAFE_FREE (retbuf);
		return NULL;
	}
	return retbuf;
}

char *str_concat4 (const char * const s1, const char * const s2, const char * const s3, const char * const s4)
{
	char *retbuf = NULL;

	if (asprintf(&retbuf, "%s%s%s%s", s1, s2, s3, s4) == -1)
	{
		if (retbuf != NULL)
			SAFE_FREE (retbuf);
		return NULL;
	}
	return retbuf;
}

char *str_concat5 (const char * const s1, const char * const s2, const char * const s3, const char * const s4, const char * const s5)
{
	char *retbuf = NULL;

	if (asprintf(&retbuf, "%s%s%s%s%s", s1, s2, s3, s4, s5) == -1)
	{
		if (retbuf != NULL)
			SAFE_FREE (retbuf);
		return NULL;
	}
	return retbuf;
}

char *file_get_contents (const char *const filename)
{
	struct stat statbuf;
	int fd;
	size_t offset = 0;
	size_t rd = 0;
	size_t sz;

	if ((fd = open (filename, O_RDONLY)) == -1)
		return NULL;

	if (fstat (fd, &statbuf) == -1)
		return NULL;

	char *strbuf = malloc (statbuf.st_size + 1);
	if (strbuf == NULL)
		return NULL;

	sz = statbuf.st_size;
	strbuf [sz] = '\0';

	while ((rd = read (fd, strbuf + offset, sz)) > 0)
	{
		if (rd == 0)
		    break; // EOF

		offset += rd;
		if (rd == sz)
		    break; // entire file has been read
		else if (rd < sz) {
		    sz -= rd;
	        }
	}

	assert (offset <= sz);

	strbuf [offset] = '\0';

	close (fd);
	return strbuf;
}

bool is_sufficiently_complex (const char * const passwd)
{
	bool sufficient = false;
	int digits = 0, upper = 0, lower = 0;

	for (const char *p = passwd; *p; p++)
	{
		     if (isdigit (*p)) digits ++;
		else if (isupper (*p)) upper  ++;
		else if (islower (*p)) lower  ++;
	}
	if (digits > 0 && upper > 0 && lower > 0)
		sufficient = true;
	
	return sufficient;
}

char *file_get_secret (const char *const filename)
{
	struct stat statbuf;
	int fd;
	size_t offset = 0;
	size_t rd = 0;
	size_t sz;

	if ((fd = open (filename, O_RDONLY)) == -1)
		return NULL;

	if (fstat (fd, &statbuf) == -1)
		return NULL;

	/* eliminating the possibility of a race condition with loose perms */
        if (statbuf.st_uid != 0 || (statbuf.st_mode & (S_IRWXG | S_IRWXO)))
	{
		compromised = true;
		aux_errno = AUX_COMPROMISED_SECRET;
		close (fd);
		// force the administrator to change compromised secret
		fd = open (filename, O_RDWR);
		ftruncate (fd, 0);
		close (fd);
                return NULL;
	}

	sz = statbuf.st_size;

	char *strbuf = (char *) calloc (1, statbuf.st_size + 1);
	if (strbuf == NULL)
		return NULL;

	strbuf [sz] = '\0';

	while ((rd = read (fd, strbuf + offset, sz)) > 0)
	{
		if (rd == 0)
		    break; // EOF

		offset += rd;
		if (rd == sz)
		    break; // entire file has been read
		else if (rd < sz) {
		    sz -= rd;
	        }
	}
	close (fd);

	assert (offset <= sz);

	strbuf [offset] = '\0';

	// secret is always needed trimmed, so we'll attempt to clean up the code ...
	int len = offset;
	int destlen;
	const char *p, *q;

	for (p = strbuf; *p && isspace (*p); p++);
	for (q = strbuf + len - 1; *q && isspace (*q); q--);
	* ((char *)q + 1) = '\0';
	destlen = q - p + 1;
	// printf ("source='%s' p='%s' q='%s' q-p=%ld destlen=%d\n", source, p, q, q-p, destlen);
	if (p > strbuf)
		memmove (strbuf, p, destlen);
	strbuf [destlen] = '\0';

	if (strlen (strbuf) < 16 || is_sufficiently_complex (strbuf) == false)
	{
		compromised = true;
		aux_errno = AUX_WEAK_SECRET;
		return NULL;
	}

	return strbuf;
}

mode_t fileperms (const char * const filename)
{
        struct stat statbuf;

	if (stat (filename, &statbuf) == -1)
		return -1;

	return statbuf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
}

char *file_get_contents_trimmed (const char * const filename)
{
	char *contents = file_get_contents (filename);
	char *retval;

	if (contents == NULL)
		return (NULL);

	retval = trim (contents);
	SAFE_FREE (contents);
	return retval;
}

/*
enum aux_errno_t {
        AUX_OK,
        AUX_COMPROMISED_SECRET,
        AUX_COMPROMISED_NONCE,
        AUX_COMPROMISED_SERIAL
};

*/

const char *aux_errstr[] = {
	"No error",
	"Compromised secret",
	"Secret too weak",
	"Compromised nonce",
	"Compromised serial",
	"World writable config file",
	NULL
};

const char * const aux_strerror (void)
{
	if (aux_errno < 0 || aux_errno >= (sizeof (aux_errstr) / sizeof (aux_errstr [0]) - 1))
		return "Unknown error.";

	return aux_errstr [aux_errno];
}

#ifdef MAIN

#include <stdio.h>

int main (int argc, char *argv[])
{
	char * serial, * nonce_ctr = NULL;

	char *s1 = "BeeABBeeoBodBaBdOdPQBBgDQgDdp";
	// char *s1 = "BeeABBeeoBodBaBdOd";
	char *s2 = "\n\n\t8b\n\n\t\nb&\nb b  \n%%nb%%%\n%\nQ";

	aux_errno = 0; printf ("%s\n", aux_strerror());
	aux_errno = 1; printf ("%s\n", aux_strerror());
	aux_errno = 2; printf ("%s\n", aux_strerror());
	aux_errno = 3; printf ("%s\n", aux_strerror());
	aux_errno = 4; printf ("%s\n", aux_strerror());
	printf ("hex='%s'\n", bin2hex ("abcd\r\n\0\0abcd", 12));
	printf ("hex='%s'\n", bin2hex ("abcd\r\n\0\0", 8));
	printf ("xor_strings3_hex='%s'\n", xor_strings3_hex ("\x11\x22\x11\x22", "\x44\x44\x44\x44", "\x55\x66\x55\x66"));
	printf ("xor_strings3_hex='%s'\n", xor_strings3_hex ("\x61\x22\x11\x22", "\x01\x44\x44\x44", "\x02\x66\x55\x66"));
	printf ("xor_strings3_hex='%s'\n", xor_strings3_hex ("probni1234", "verybigsecret", "nooooooooooooooooonce"));
	printf ("xor_strings3_hex='%s'\n", xor_strings3_hex ("probni12340000000000", "verybigsecret", "nooooooooooooooooonce"));
	printf ("xor_strings3_hex='%s'\n", xor_strings3_hex ("probni12340000000000", "verybigsecret", "nooo"));

/*
	printf ("%s\n", str_concat2("prvi", "drugi"));
	printf ("%s\n", str_concat3("prvi", "drugi", "treci"));
	printf ("%s\n", str_concat4("prvi", "drugi", "treci", "cetvrti"));
	printf ("%s\n", str_concat5("prvi", "drugi", "treci", "cetvrti", "peti"));

	printf ("%s\n", my_str_concat2("prvi", "drugi"));
	printf ("%s\n", my_str_concat3("prvi", "drugi", "treci"));
	printf ("%s\n", my_str_concat4("prvi", "drugi", "treci", "cetvrti"));
	printf ("%s\n", my_str_concat5("prvi", "drugi", "treci", "cetvrti", "peti"));
	char *s = str_concat3(get_random_string(), get_random_string(), get_random_string());
	printf ("%s\n", s != NULL ? s : "NULL" );
	s = str_concat5(get_random_string(), get_random_string(), get_random_string(), get_random_string(), get_random_string());
	printf ("%s\n", s != NULL ? s : "NULL" );
	printf ("%s\n", s1);
	printf ("%s\n", xor_strings (s1, s2, strlen (s1)));
	printf ("%s\n", xor_strings3 (s1, s2, s2, strlen (s1)));
	printf ("%s\n", xor_strings3 ("probni1234", "verybigsecret", "nooooooooooooooooonce", 21));
	// printf ("%s", file_get_contents (argv[1]));
	printf ("%s\n", get_random_string ());
	printf ("%s\n", get_random_string ());
	printf ("%s\n", get_random_string ());
	if ((serial = get_serial()) != NULL)
		printf ("%s\n", serial);
	if ((nonce_ctr = get_nonce_ctr()) != NULL)
		printf ("%s\n", nonce_ctr);
	else printf ("nonce_ctr = (null)\n");
	if ((serial = get_serial()) != NULL)
		printf ("%s\n", serial);
	if ((serial = get_serial()) != NULL)
		printf ("%s\n", serial);
	if ((serial = get_serial()) != NULL)
		printf ("%s\n", serial);
	char *fstr = NULL, *trimstr = NULL;
*/
/*
	if (argc == 2) {
	    printf ("'%s'", trimstr = trim (fstr = file_get_contents (argv[1])));
	    free (fstr);
	    free (trimstr);
	    fprintf (stderr, "isspace_str = %d\n", isspace_str (argv[1]));
	} else {
	    fprintf (stderr, "Usage: %s file\n", argv[0], argv[1]);
	    exit (1);
	}
*/
}

#endif

