/**
 * Nginx Sobek module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "globals.h"

// We need this here as a declaration only; it is defined in main header file which will resolve it at runtime.
extern ngx_module_t ngx_http_sobek_module;

/**
 * Debug to file with flish
 */
void sobek_debug(char *format, ...) {
	FILE *f = fopen("/mnt/cdn/tmp/debug", "a");

	va_list arglist;
	va_start(arglist, format);
	vfprintf(f, format, arglist);
	va_end(arglist);
	fprintf(f, "\n");
	fclose(f);
}

/**
 * Polyfill for memstr()
 */
char *memstr(char *haystack, char *needle, int64_t size) {
	char *p;

	for (p = haystack; p <= (haystack - strlen(needle) + size); p++) {
		if (memcmp(p, needle, strlen(needle)) == 0)
			return p;
	}

	return NULL;
}

/**
 * Convert Nginx string to normal using Nginx pool
 */
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str) {
	char *ret;

	if (! ngx_str.len)
		return NULL;

	if ((ret = ngx_pcalloc(pool, ngx_str.len + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, pool->log, 0, "Failed to allocate %l bytes in from_ngx_str().", ngx_str.len + 1);
		return NULL;
	}

	bzero(ret, ngx_str.len + 1);
	memcpy(ret, ngx_str.data, ngx_str.len);
	return ret;
}


/**
 * Convert Nginx string to normal using malloc
 */
char *from_ngx_str_malloc(ngx_pool_t *pool, ngx_str_t ngx_str) {
	char *ret;

	if (! ngx_str.len)
		return NULL;

	if ((ret = calloc(ngx_str.len + 1), 1) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, pool->log, 0, "Failed to allocate %l bytes in from_ngx_str().", ngx_str.len + 1);
		return NULL;
	}

	memcpy(ret, ngx_str.data, ngx_str.len);
	return ret;
}

/**
 * Encode a string to base16 string
 */
void base16_encode(unsigned char *in, int len, unsigned char *out) {
	size_t  i;

	for (i=0; i < len; i++) {
		out[i * 2]   = "0123456789abcdef"[in[i] >> 4];
		out[i * 2 + 1] = "0123456789abcdef"[in[i] & 0x0F];
	}
	//out[len * 2] = '\0';
}

/**
 * Init instance
 */
void globals_init(ngx_http_request_t *r) {
	ngx_http_sobek_loc_conf_t *sobek_loc_conf;

	if (globals.init)
		return;

	// Get config
	sobek_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_sobek_module);

	globals.sign_key = from_ngx_str_malloc(r->pool, sobek_loc_conf->sign_key);
	globals.init = TRUE;
}

/**
 * Trim a string and get it back as a 64-bit signed int (-1 for empty strings, -2 for malloc error)
 */
int64_t get_trimmed_int(char *in) {
	char *s1, *s2;
	long ret = -1;

	if ((s1 = strdup(in)) == NULL)
		return -2;
	s2 = s1;

	// Kill any trailing space (replace with NULL)
	while ( *(s1 + strlen(s1) -1) == 32)
		memset(s1 + strlen(s1) - 1, '\0', 1);

	// Kill any leading space (shift forward a copy of the pointer)
	while ( *(s2) == 32 )
		s2++;

	// Use default -1 for empty values
	if (strlen(s2))
		ret = atol(s2);

	free(s1);

	return ret;
}


/**
 * Extract header etag
 */
char *trim_quotes(ngx_http_request_t *r, char *s) {
	char *ret, *s1, *s2;

	s1 = strchr(s, '"');
	s2 = strrchr(s, '"');
	if ((s1 == s) && (s2 == s + strlen(s) - 1)) {
		if ((ret = ngx_pcalloc(r->pool, strlen(s) - 1)) == NULL)
			return NULL;

		strncpy(ret, s + 1, strlen(s) - 2);
	}
	else
		ret = s;

	return ret;
}

