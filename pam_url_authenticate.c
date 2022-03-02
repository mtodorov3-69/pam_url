// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url
// GPLv2 - Mirsad Goran Todorovac, 2022-02-03, adding skip_password option

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pam_url.h"
#include "aux.h"

extern char *recvbuf;

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{ // by now, a dummy
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
	pam_url_opts opts;
	int ret = 0;

	if ( PAM_SUCCESS != pam_get_item(pamh, PAM_USER, &opts.user) )
	{
		ret++;
		debug(pamh, "Could not get user item from pam.");
	}

	if( !opts.skip_password && (PAM_SUCCESS != pam_get_item(pamh, PAM_AUTHTOK, &opts.passwd)) )
	{
		ret++;
		debug(pamh, "Could not get password item from pam.");
	}

	if ( PAM_SUCCESS != pam_get_item(pamh, PAM_RHOST, (const void **)&opts.clientIP) )
	{
		ret++;
		debug(pamh, "Could not get PAM_RHOST from pam.");
	} else
		debug(pamh, "PAM_RHOST retrieved from pam.");
		

	if( PAM_SUCCESS != parse_opts(&opts, argc, argv, PAM_SM_AUTH) )
	{
		ret++;
		if (compromised)
			debug(pamh, "Config error: %s", aux_strerror());
		debug(pamh, "Could not parse module options.");
	}
	else if (!is_legal_hashalg (opts.hashalg))
	{
		debug(pamh, "%s: Unknown hash algorithm.", opts.hashalg);
		return PAM_SERVICE_ERR;
	}
	else if (!file_is_secure (opts.secret_file))
	{
		debug(pamh, "%s: Compromised permissions on secret file. Refusing to run.", opts.secret_file);
		return PAM_SYSTEM_ERR;
	}
	else if (!dir_is_secure (PAM_URL_DIR))
	{
		debug(pamh, "%s: Insecure permissions (must be 0700). Refusing to run.", PAM_URL_DIR);
		return PAM_SYSTEM_ERR;
	}

	if( !opts.skip_password && (!opts.use_first_pass || NULL == opts.passwd) )
	{
		if( NULL != opts.passwd ) {
			opts.first_pass = strdup(opts.passwd);
		}

		if( PAM_SUCCESS != get_password(pamh, &opts) )
		{
			debug(pamh, "Could not get password from user. No TTY?");
			return PAM_AUTH_ERR;
		}
	}
	debug(pamh, "TEMP: entering fetch_url()");

	if( PAM_SUCCESS != fetch_url(pamh, opts) )
	{
		ret++;
		debug(pamh, "Could not fetch URL.");
	}

	if( PAM_SUCCESS != check_rc(opts) )
	{
                debug(pamh, "Wrong Return Code: opts.ret_code=%s, recvbuf=%s", opts.ret_code, recvbuf);
		ret++;
		// debug(pamh, "Wrong Return Code.");
	}

	cleanup(&opts);

	if( 0 == ret )
	{
		return PAM_SUCCESS;
	}
	else
	{
		debug(pamh, "Authentication failed.");
		usleep(1000000);
		return PAM_AUTH_ERR;
	}
}
