/*
 * Mirsad Goran Todorovac 2022 GNU Copyleft.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

#include "aux.h"

char *get_random_string (void)
{
	struct timespec tv;
	struct drand48_data buffer;
	double result, result2;
	char *randomstr = NULL;

	if (clock_gettime (CLOCK_MONOTONIC, &tv) == -1)
		return NULL;
	
	srand48_r (tv.tv_nsec, &buffer);
	drand48_r (&buffer, &result);
	drand48_r (&buffer, &result2);
	int ret = asprintf (&randomstr, "%lf%ld%ld%lf", result, tv.tv_sec, tv.tv_nsec, result2);
	if (ret == -1)
		return NULL;
	char * hashstr = sha256_string (randomstr);
	free (randomstr);
	return hashstr;
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

	strbuf [offset] = '\0';

	close (fd);
	return strbuf;
}

#ifdef MAIN

#include <stdio.h>

int main (int argc, char *argv[])
{
	// printf ("%s", file_get_contents (argv[1]));
	// printf ("%s\n", get_random_string ());
	char *fstr = NULL, *trimstr = NULL;
	if (argc == 2) {
	    printf ("'%s'", trimstr = trim (fstr = file_get_contents (argv[1])));
	    free (fstr);
	    free (trimstr);
	} else {
	    fprintf (stderr, "Usage: %s file\n", argv[0], argv[1]);
	    exit (1);
	}
}

#endif

