// pam_url - GPLv2, Sascha Thomas Spreitzer, https://fedorahosted.org/pam_url
// GPLv2, Mirsad Goran Todorovac, 2022-02-03, adding option for passwordless auth
//                                            with pam_url (i.e. with certs and additional
//                                            validation).

#include "pam_url.h"
#include "aux.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

char* recvbuf = NULL;
size_t recvbuf_size = 0;
static config_t config;
bool  pam_url_debug = false;

void debug(pam_handle_t* pamh, const char * const fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	pam_vsyslog(pamh, LOG_ERR, fmt, ap);
	va_end(ap);
	// pam_syslog(pamh, LOG_ERR, "%s", msg);
}

int get_password(pam_handle_t* pamh, pam_url_opts* opts)
{
	char* p = NULL;
	const char *prompt;

	if(config_lookup_string(&config, "pam_url.settings.prompt", &prompt) == CONFIG_FALSE)
		prompt = DEF_PROMPT;
	
	pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &p, "%s", prompt);
	
	if( NULL != p && strlen(p) > 0)
	{
		opts->passwd = p;
		return PAM_SUCCESS;
	}
	else
	{
		return PAM_AUTH_ERR;
	}
}


int parse_opts(pam_url_opts *opts, int argc, const char *argv[], int mode)
{
#if defined(DEBUG)
	pam_url_debug = true;
#else
	pam_url_debug = false;
#endif
	opts->configfile = NULL;
	opts->use_first_pass = false;
	opts->prepend_first_pass = false;
	opts->skip_password = false;
	opts->first_pass = NULL;
	
	if(argc > 0 && argv != NULL)
	{	
	int next_arg;
		for(next_arg = 0; next_arg < argc; next_arg++)
		{
			if(strcmp(argv[next_arg], "debug") == 0)
			{
				pam_url_debug = true;
				continue;
			}
			
			if(strncmp(argv[next_arg], "config=", 7) == 0)
			{
				// Skip the first 7 chars ('config=').
				opts->configfile = strdup(argv[next_arg] + 7);
				continue;
			}
			
			if(strcmp(argv[next_arg], "use_first_pass") == 0)
			{
				opts->use_first_pass = true;
				continue;
			}

			if(strcmp(argv[next_arg], "prepend_first_pass") == 0)
			{
				opts->prepend_first_pass = true;
				continue;
			}

			if(strcmp(argv[next_arg], "skip_password") == 0)
			{
				opts->skip_password = true;
				continue;
			}
		}
	}
	
	if(opts->configfile == NULL)
		opts->configfile = strdup("/etc/pam_url.conf");
	
	switch(mode)
	{
		case PAM_SM_ACCOUNT:
			opts->mode = "PAM_SM_ACCOUNT";
			break;
		case PAM_SM_SESSION:
			opts->mode = "PAM_SM_SESSION";
			break;
		case PAM_SM_PASSWORD:
			opts->mode = "PAM_SM_PASSWORD";
			break;
		case PAM_SM_AUTH:
		default:
			opts->mode = "PAM_SM_AUTH";
			break;
	}
	
	config_init(&config);
	config_read_file(&config, opts->configfile);

	// General Settings
	if(config_lookup_string(&config, "pam_url.settings.url", &opts->url) == CONFIG_FALSE)
		opts->url = DEF_URL;

	if(config_lookup_string(&config, "pam_url.settings.returncode", &opts->ret_code) == CONFIG_FALSE)
		opts->ret_code = DEF_RETURNCODE;

	if(config_lookup_string(&config, "pam_url.settings.userfield", &opts->user_field) == CONFIG_FALSE)
		opts->user_field = DEF_USER;

	if(config_lookup_string(&config, "pam_url.settings.passwdfield", &opts->passwd_field) == CONFIG_FALSE)
		opts->passwd_field = DEF_PASSWD;

	if(config_lookup_string(&config, "pam_url.settings.extradata", (const char **)&opts->extra_field) == CONFIG_FALSE)
		opts->extra_field = DEF_EXTRA;

	if(config_lookup_string(&config, "pam_url.settings.secret", (const char **)&opts->secret_file) == CONFIG_FALSE)
		opts->secret_file = DEF_SECRET;

	if(config_lookup_string(&config, "pam_url.settings.hashalg", (const char **)&opts->hashalg) == CONFIG_FALSE)
		opts->hashalg = DEF_HASHALG;

	// SSL Options
	if(config_lookup_string(&config, "pam_url.ssl.client_cert", &opts->ssl_cert) == CONFIG_FALSE)
		opts->ssl_cert = DEF_SSLCERT;

	if(config_lookup_string(&config, "pam_url.ssl.client_key", &opts->ssl_key) == CONFIG_FALSE)
		opts->ssl_key = DEF_SSLKEY;
	if(config_lookup_string(&config, "pam_url.ssl.ca_cert", &opts->ca_cert) == CONFIG_FALSE)
		opts->ca_cert = DEF_CA_CERT;

	if(config_lookup_bool(&config, "pam_url.ssl.verify_host", (int *)&opts->ssl_verify_host) == CONFIG_FALSE)
		opts->ssl_verify_host = true;

	if(config_lookup_bool(&config, "pam_url.ssl.verify_peer", (int *)&opts->ssl_verify_peer) == CONFIG_FALSE)
		opts->ssl_verify_peer = true;

	return PAM_SUCCESS;
}
	

size_t curl_wf(void *ptr, size_t size, size_t nmemb, void *stream)
{
	size_t oldsize=0;

	if( 0 == size * nmemb )
		return 0;

	if( NULL == recvbuf )
	{
		if( NULL == ( recvbuf = calloc(nmemb, size) ) )
		{
			return 0;
		}
	}

	// Check the multiplication for an overflow
	if (((nmemb * size) > (SIZE_MAX / nmemb)) ||
			// Check the addition for an overflow
			((SIZE_MAX - recvbuf_size) < (nmemb * size))) {
		// The arithmetic will cause an integer overflow
		return 0;
	}
	if( NULL == ( recvbuf = realloc(recvbuf, recvbuf_size + (nmemb * size)) ) )
	{
		return 0;
	}
	else
	{
		oldsize = recvbuf_size;
		recvbuf_size += nmemb * size;
		memcpy(recvbuf + oldsize, ptr, size * nmemb);
		return(size*nmemb);
	}
}

int curl_debug(CURL *C, curl_infotype info, char * text, size_t textsize, void* pamh)
{
	debug((pam_handle_t*)pamh, text);
	return 0;
}

char *rethash = NULL;

int fetch_url(pam_handle_t *pamh, pam_url_opts opts)
{
	CURL* eh = NULL;
	char* post = NULL;
	int ret = 0;
	char* nonce = NULL, *serial = NULL;

	char *passwd = NULL, *safe_passwd = NULL;

	char *urlsafe_fields = NULL, *hmac_fields = NULL;
	char *secret = NULL, *trim_secret = NULL;
	char *xor_passwd = NULL;
	char *hash = NULL;

	bool success = false;

	if( NULL == opts.user )
		opts.user = "";

	if( NULL == opts.passwd )
		opts.passwd = "";
	
	if( NULL == opts.clientIP )
		opts.clientIP = "";
	
	if( 0 != curl_global_init(CURL_GLOBAL_ALL) )
		goto curl_error_1;

	if( NULL == (eh = curl_easy_init() ) )
		goto curl_error_2;

	char *safe_user = curl_easy_escape(eh, opts.user, 0);
	if( safe_user == NULL )
		goto curl_error_3;

	debug(pamh, "Getting a random string.");
	success = (nonce       = get_unique_nonce())			&&
		  (serial      = get_serial())				&&
		  (secret      = file_get_contents (opts.secret_file))	&&
		  (trim_secret = trim (secret));

	FORGET (secret);  // Keep secret in memory as little as possible

	if (success == false)
		goto curl_error_5;

	debug(pamh, "Read the secret. Not logging it.");

	if( !opts.skip_password ) {
		if (strncmp (opts.url, "https://", 8) != 0 ) {
			debug(pamh, "ALERT: Attempt to send password in clear refused. Make sure that you are using HTTPS!");
			goto curl_error;
		}
		if( opts.prepend_first_pass && NULL != opts.first_pass )
		{
			char *combined = NULL;

			debug(pamh, "Prepending previously used password.");
			if( asprintf(&combined, "%s%s", opts.first_pass, (const char *)opts.passwd) < 0 ||
				combined == NULL )
			{
				debug(pamh, "Out of memory: %s", strerror (errno));
				FORGET(combined);
				goto curl_error_5;
			}

			passwd = strdup (combined);
			FORGET(combined);
		}
		else
		{
			passwd = strdup (opts.passwd);
			FORGET_NOT_FREE(opts.passwd);
		}
	} else {
		debug(pamh, "WARNING: You have requested passwordless authentication. Make sure this is not the only and sufficient auth pam module.");
		passwd = strdup ("");
	}
	if( passwd == NULL )
		goto curl_error_5;

	if (strlen (passwd) > strlen (trim_secret) || strlen (passwd) > strlen (nonce))
	{
		debug(pamh, "Password too long. The encryption is not defined for passwd > secret.");
		goto curl_error_5;
	}

	debug(pamh, "Preparing masked password.");
	if ((xor_passwd = xor_strings3_hex (passwd, trim_secret, nonce)) == NULL)
		goto curl_error_5;

	debug(pamh, "Preparing safe password.");
	if ((safe_passwd = curl_easy_escape(eh, xor_passwd, 0)) == NULL)
		goto curl_error_5;

	FORGET (passwd);

	debug(pamh, "Preparing post fields.");
	ret = asprintf(&urlsafe_fields, "%s=%s&%s=%s&mode=%s&clientIP=%s&nonce=%s&serial=%s", opts.user_field,
							safe_user,
							opts.passwd_field,
							safe_passwd,
							opts.mode,
							(const char *)opts.clientIP,
							nonce,
							serial/*,
							opts.extra_field*/);
	FORGET_NOT_FREE (safe_passwd);
	curl_free(safe_passwd);	
	curl_free(safe_user);
	debug(pamh, "Wrote the POST fields: %s.", urlsafe_fields);

	if (ret == -1)
		// If this happens, the contents of post are undefined, we could
		// end up freeing an uninitialized pointer, which could crash (but
		// should not have security implications in this context).
		goto curl_error;

	hmac_fields = my_str_concat5 (opts.user, xor_passwd, opts.mode, opts.clientIP, serial);
	FORGET (xor_passwd);
	debug(pamh, "Wrote the hmac fields: %s.", hmac_fields);

	if (hmac_fields == NULL)
		goto curl_error;

	success =  (hash    = hashsum_fmt(opts.hashalg, "%s%s%s%s", nonce, hmac_fields, trim_secret, nonce)) &&
		   (rethash = hashsum_fmt(opts.hashalg, "%s%s%s%s", nonce, serial, trim_secret, nonce));

	FORGET (trim_secret);  // Keep secret in memory as little as possible
	SAFE_FREE (nonce);
	SAFE_FREE (hmac_fields);
	SAFE_FREE (serial);

	if (!success)
		goto curl_error_4;

	debug (pamh, "rethash = %s", rethash);

	post = str_concat3 (urlsafe_fields, "&hash=", hash);

	SAFE_FREE (urlsafe_fields);
	SAFE_FREE (hash);

	if (post == NULL)
		goto curl_error;

	if( 1 == pam_url_debug)
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_VERBOSE, 1) )
			goto curl_error;

		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_DEBUGDATA, pamh) )
			goto curl_error;

		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_DEBUGFUNCTION, curl_debug) )
			goto curl_error;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_POSTFIELDS, post) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_USERAGENT, USER_AGENT) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, curl_wf) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_URL, opts.url) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSLCERT, opts.ssl_cert) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSLCERTTYPE, "PEM") )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSLKEY, opts.ssl_key) )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSLKEYTYPE, "PEM") )
		goto curl_error;

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_CAINFO, opts.ca_cert) )
		goto curl_error;

	if( opts.ssl_verify_host == true )
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYHOST, 2) )
			goto curl_error;
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYHOST, 0) )
			goto curl_error;
	}

	if( opts.ssl_verify_peer == true )
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, 1) )
			goto curl_error;
	}
	else
	{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, 0) )
			goto curl_error;
	}

	if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_FAILONERROR, 1) )
		goto curl_error;

	if( CURLE_OK != curl_easy_perform(eh) )
		goto curl_error;

	// No errors
	SAFE_FREE (post);
	curl_easy_cleanup(eh);
	curl_global_cleanup();
	return PAM_SUCCESS;

curl_error_5:
	curl_free(safe_user);
	if (secret == NULL)
	{
		debug(pamh, "Failed the secret: %s", strerror (errno));
		debug(pamh, "secrets=%s", opts.secret_file);
	} else
		FORGET(secret);
	if (serial == NULL)
		debug(pamh, "Didn't get a serial.");
	else
		SAFE_FREE(serial);
	if (nonce == NULL)
		debug(pamh, "Didn't get myself a nonce.");
	else
		SAFE_FREE(nonce);
curl_error:
	debug(pamh, "curl_error: freeing memory");
	// double check everything for memory leaks
	if (xor_passwd  != NULL)
		FORGET (xor_passwd);
	if (passwd      != NULL)
		FORGET (passwd);
	if (nonce       != NULL)
		SAFE_FREE(nonce);
	if (serial      != NULL)
		SAFE_FREE(serial);
	if (hmac_fields != NULL)
		SAFE_FREE(hmac_fields);
	if (post        != NULL)
		SAFE_FREE(post);
curl_error_4:
	debug(pamh, "curl_error_4: freeing memory");
	if (urlsafe_fields != NULL)
		SAFE_FREE (urlsafe_fields);
	if (hash           != NULL)
		SAFE_FREE (hash);
	if (rethash        != NULL)
		SAFE_FREE (rethash);
curl_error_3:
	curl_easy_cleanup(eh);
curl_error_2:
	curl_global_cleanup();
curl_error_1:
	return PAM_AUTH_ERR;
}

int check_rc(pam_url_opts opts)
{
	int len = strlen(opts.ret_code);
	int retval;

	if( NULL == recvbuf )
	{
		retval = PAM_AUTH_ERR;
	}

	if( len <= recvbuf_size && 0 == strncmp(opts.ret_code, recvbuf, len) )
	{
		if (strncmp (recvbuf + len + 1, rethash, strlen(rethash)) == 0)
			retval = PAM_SUCCESS;
		else
			retval = PAM_AUTH_ERR;
	}
	else
	{
		retval = PAM_AUTH_ERR;
	}
	if (rethash != NULL)
		SAFE_FREE (rethash);
	return retval;
}

void cleanup(pam_url_opts* opts)
{
	if( NULL != recvbuf )
	{
		free(recvbuf);
		recvbuf = NULL;
	}

	recvbuf_size=0;
	free(opts->configfile);
	config_destroy(&config);
}
