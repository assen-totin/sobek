/**
 * Nginx Sobek module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "utils.h"

// We need this here as a declaration only; it is defined in main header file which will resolve it at runtime.
extern ngx_module_t ngx_http_sobek_module;

/**
 * GET Content handler
 */
ngx_int_t sobek_handler_get(ngx_http_request_t *r) {
	ngx_int_t ret = NGX_OK;
	session_t *session;
	struct timeval tv;
	int res;
	unsigned int dig_len=0, i, json_len;
	unsigned char *random, *challenge, *to_sign, *sig, *sig_b16, *json;
	ngx_buf_t *buf = NULL;
	ngx_chain_t *out, *bufs;
	ngx_int_t ret = NGX_OK;
	const EVP_MD *ossl_alg;

	// Inti globals if this is the first request on current thread
	globals_init(r);

	// Get current timestamp
	if ((res = gettimeofday(&tv, NULL)) < 0) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to get current time: %s", strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get random & convert it to Base-16 challenge
	if ((random = ngx_pcalloc(r->pool, CHALLENGE_LENGTH)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for random data.", CHALLENGE_LENGTH);
		return upload_cleanup(r, upload, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	if ((challenge = ngx_pcalloc(r->pool, 2 * CHALLENGE_LENGTH)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for challenge.", 2 * CHALLENGE_LENGTH);
		return upload_cleanup(r, upload, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	if ((res = RAND_bytes(random, CHALLENGE_LENGTH)) < 1) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to generate %l bytes of random data: %s", CHALLENGE_LENGTH, ERR_error_string(ERR_get_error(), NULL))
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	base16_encode(random, CHALLENGE_LENGTH, challenge);

	// Prepare data to sign (does not have to be a NULL-terminated string, but this way we can log it)
	if ((to_sign = ngx_pcalloc(r->pool, 2 * CHALLENGE_LENGTH + 11)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for signing data.", 2 * CHALLENGE_LENGTH + 11);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	sprintf(to_sign, "%i@", tv.tv_sec);
	memcpy(to_sign + strlen(to_sign), random, CHALLENGE_LENGTH);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Data to sign: %s", to_sign);

	// Compute signature
	if ((dig = ngx_pcalloc(r->pool, SIGNATURE_LENGTH)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for signature", SIGNATURE_LENGTH);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ossl_alg = EVP_sha256();
	HMAC(ossl_alg, globals->sign_key, strlen(globals->sign_key), (const unsigned char *)to_sign, strlen(to_sign), sig, &sig_len);

	// Convert signature to Base-16
	if ((sig_b16 = ngx_pcalloc(r->pool, 2 * SIGNATURE_LENGTH + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for signature in Base-16.", 2 * SIGNATURE_LENGTH + 11);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	base16_encode(sig, SIGNATURE_LENGTH, sig_b16);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "HMAC: %s", sig_b16);


	// Prepare output JSON
/*
{
timestamp:1234567890,
challenge:"abcdef...",
signature:"0123456789abcdef..." 
}

1
10 + 10 + 1
11 + 2*CHALLENGE_LENGTH + 2
11 + 2*SIGNATURE_LENGTH + 1
1
+ NULL byte
*/
	json_len = 1 + 10 + 10 + 1 + 11 + 2 * CHALLENGE_LENGTH + 2 + 11 + 2 * SIGNATURE_LENGTH + 1 + 1 + 1;	
	if ((json = ngx_pcalloc(r->pool, json_len)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for JSON.", json_len);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JSON length: %l", json_len);

	strcpy(json, "{timestamp:");
	sprintf(json + strlen(json), "%i", tv.tv_sec);
	strcpy(json + strlen(json), ",challenge:\"");
	memcpy(json + strlen(json), challenge, 2 * CHALLENGE_LENGTH)
	strcpy(json + strlen(json), "\",signature:\"");
	memcpy(json + strlen(json), sig_b16, 2 * SIGNATURE_LENGTH)
	strcpy(json + strlen(json), "\"}");
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JSON: %s", json);

	// Prepare output chain
	out = ngx_alloc_chain_link(r->pool);
	if (out == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for buffer chain.", sizeof(ngx_chain_t));
		return upload_cleanup(r, upload, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Prepare output buffer
	if ((buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for response buffer.", sizeof(ngx_buf_t));
		return upload_cleanup(r, upload, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Prepare output chain; hook the buffer
	out->buf = buf;
	out->next = NULL; 

	// Set the buffer
	buf->pos = (u_char *) json;
	buf->last = (u_char *) json + json_len;
	buf->mmap = 1; 
	buf->last_buf = 1; 

	// Status
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = buf->last - buf->pos;

	// Content-Type 
	r->headers_out.content_type.len = strlen(CONTENT_TYPE_A_J);
	r->headers_out.content_type.data = (u_char*) CONTENT_TYPE_A_J;

	ret = ngx_http_send_header(r);
	ret = ngx_http_output_filter(r, out);
	ngx_http_finalize_request(r, ret);
}

