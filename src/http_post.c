/**
 * Nginx Sobek module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "globals.h"
#include "utils.h"

/**
 * POST and PUT request body processing callback
 */
void sobek_handler_post (ngx_http_request_t *r) {
	int res;
	int cookie_len;
	unsigned int sig_len;
	long content_length, rb_pos = 0;
	time_t exp;
	off_t len = 0, len_buf;

	char *content_length_z, *content_type, *part = NULL, *part_pos = NULL,  *part_end;
	char *sig_b16;
	char *rb, *form_field_name = NULL, *form_field_value = NULL;
	char *ff_timestamp = NULL, *ff_challenge = NULL, *ff_signature = NULL, *ff_solution = NULL;
	char *hash_b16;
	char pld, *pld_b16, *cookie;
	unsigned char *to_hash, *hash, *sig;

	ngx_chain_t *out, *bufs;
	ngx_int_t ret = NGX_OK;
	ngx_buf_t *buf = NULL;

	struct timeval tv;
	struct tm gmt;
	const EVP_MD *ossl_alg;

	// Init globals if this is the first request on current thread
	globals_init(r);

	// Check if we have body
	if (r->request_body == NULL)
		return ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "POST pocessing request.");

	// Extract content type from header
	content_type = from_ngx_str(r->pool, r->headers_in.content_type->value);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "POST found header Content-Type: %s", content_type);
	if (strstr(content_type, CONTENT_TYPE_A_XWFU))
		;
	else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "POST Content-Type %s not supported", content_type);
		return ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
	}

	// Extract content length from header
	content_length_z = from_ngx_str(r->pool, r->headers_in.content_length->value);
	if (! content_length_z) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "POST Content-Length not set");
		return ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
	}
	content_length = atol(content_length_z);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "POST found header Content-Length: %l", content_length);

	// Extract POST request body
	if ((rb = ngx_pcalloc(r->pool, content_length)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to allocate %l bytes for request body", content_length);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	for (bufs = r->request_body->bufs; bufs; bufs = bufs->next) {
		len_buf = ngx_buf_size(bufs->buf);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "POST request body: found new memory buffer with size: %l", len_buf);
		len += len_buf;

		memcpy(rb + rb_pos, bufs->buf->start, len_buf);
		rb_pos += len_buf;
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "POST request body: total memory buffer length: %l", len);
	if (len != content_length) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "POST request body mismatch: Content-Length %l, total memory buffers %l bytes", content_length, len);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Process application/x-www-form-urlencoded
	// Traverse the request body
	part = rb;
	while (part) {
		// Find next =
		if ((part_pos = memchr(part, '=', rb - part + content_length)) == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "POST request A/XWFU: could not find next key-value delimiter");
			return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
		part_end = part_pos;
			
		// Extract form field name
		if ((form_field_name = ngx_pcalloc(r->pool, part_end - part + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to allocate %l bytes for for field name.", part_end - part + 1);
			return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
		strncpy(form_field_name, part, part_end - part);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "POST request A/XWFU: found field name %s", form_field_name);

		// Jump over the = sign
		part_pos ++;

		// Find next &
		if ((part = memchr(part, '&', rb - part_pos + content_length)) == NULL) {
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "POST request A/XWFU: reached last form field");
			part_end = rb + content_length;
		}
		else {
			part_end = part;

			// Jump over the & sign
			part ++;
		}

		// Extract form field name
		if ((form_field_value = ngx_pcalloc(r->pool, part_end - part_pos + 1)) == NULL) {
			ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to allocate %l bytes for for field name.", part_end - part_pos + 1);
			return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		}
		strncpy(form_field_value, part_pos, part_end - part_pos);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "POST request A/XWFU: found field value %s", form_field_value);

		// Decide what to do with the field
		if (! strcmp(form_field_name, "timestamp"))
			ff_timestamp = form_field_value;
		else if (! strcmp(form_field_name, "challenge"))
			ff_challenge = form_field_value;
		else if (! strcmp(form_field_name, "signature"))
			ff_signature = form_field_value;
		else if (! strcmp(form_field_name, "solution"))
			ff_solution = form_field_value;
	}

	if (! ff_timestamp || ! ff_challenge || ! ff_signature || ! ff_solution)
		return ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

	// Verify signature
	// Prepare space for signature in Base-16
	if ((sig_b16 = ngx_pcalloc(r->pool, 2 * SIGNATURE_LENGTH + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to allocate %l bytes for signature in Base-16.", 2 * SIGNATURE_LENGTH + 1);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	if ((res = create_signature(r, atol(ff_timestamp), ff_challenge, sig_b16)) > 0)
		return ngx_http_finalize_request(r, res);

	if (memcpy(ff_signature, sig_b16, SIGNATURE_LENGTH)) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "POST signature mismatch: calculated %s received %s", sig_b16, ff_signature);
		// FIXME: Return other code here?
		return ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
	}

	// Verify timestamp is not too old
	if ((res = gettimeofday(&tv, NULL)) < 0) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to get current time: %s", strerror(errno));
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	if (tv.tv_sec - atol(ff_timestamp) > CHALLENGE_TTL) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "POST timestamp is too old: current %l, receiver %s, ttl %l", tv.tv_sec, ff_timestamp, CHALLENGE_TTL);
		// FIXME: Return other code here?
		return ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
	}

	// Verify solution
	if ((to_hash = ngx_pcalloc(r->pool, strlen(ff_challenge) + strlen(ff_solution))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to allocate %l bytes for solution verification.", strlen(ff_challenge) + strlen(ff_solution));
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	if ((hash = ngx_pcalloc(r->pool, HASH_LENGTH)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to allocate %l bytes for hash.", HASH_LENGTH);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	memcpy(to_hash, ff_challenge, strlen(ff_challenge));
	memcpy(to_hash + strlen(ff_challenge), ff_solution, strlen(ff_solution));

	SHA256(to_hash, strlen(ff_challenge) + strlen(ff_solution), hash);

	// Encode hash to Base-16 (for logging)
	if ((hash = ngx_pcalloc(r->pool, 2 * HASH_LENGTH + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to allocate %l bytes for hash in Base-16.", 2 * HASH_LENGTH + 1);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	base16_encode(hash, HASH_LENGTH, hash_b16);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "POST hash: %s", hash_b16);

	// Check if hash begins with two zeroes
	if ((*hash != 0) || (*(hash + 1) != 0)) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Solution failed");
		// FIXME: Return other code here?
		return ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
	}

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Solution verified");

	// Prepare cookie
	// Cookie consist of payload and signature, concatenated with the @ sign
	// Payload is JSON (with current timestamp + offset as TTL), convreted to Base-16 for transmission
	// Signature is also converted to Base-16 for transmission
	/*
	{
		exp:1234567890
	}
	*/
	if ((pld = ngx_pcalloc(r->pool, 17)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to allocate %l bytes for payload.", 17);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	exp = tv.tv_sec + globals.cookie_ttl;
	sprintf(pld, "{exp:%li}", exp);

	if ((pld_b16 = ngx_pcalloc(r->pool, 2*17)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "POST failed to allocate %l bytes for payload in Base-16.", 2*17);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	base16_encode((const unsigned char *) pld, strlen(pld), pld_b16);

	// Sign cookie
	// NB: we sign the payload (JSON) before it was encoded in Base-16
	if ((sig = ngx_pcalloc(r->pool, SIGNATURE_LENGTH)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie signature", SIGNATURE_LENGTH);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	ossl_alg = EVP_sha256();
	HMAC(ossl_alg, globals.sign_key, strlen(globals.sign_key), (const unsigned char *)pld, strlen(pld), sig, &sig_len);

	// Convert signature to Base-16
	if ((sig_b16 = ngx_pcalloc(r->pool, 2 * SIGNATURE_LENGTH + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie signature", SIGNATURE_LENGTH);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	base16_encode(sig, SIGNATURE_LENGTH, sig_b16);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Cookie HMAC: %s", sig_b16);

	// Prepare cookie string
	//sobek=123@456...; expires=Thu, 18 Dec 2013 12:00:00 UTC; path=/
	cookie_len = strlen(globals.cookie_name) + 1 + strlen(pld_b16) + 1 + strlen(sig_b16) + 47 + 1;
	if ((cookie = ngx_pcalloc(r->pool, cookie_len)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Failed to allocate %l bytes for cookie", cookie_len);
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}
	// Add expiration time from "exp"
	gmtime_r(&exp, &gmt);
	sprintf(cookie, "%s=%s@%s", globals.cookie_name, pld_b16, sig_b16);
	strftime(cookie + strlen(cookie), 47, "; expires=%a, %d %b %Y %H:%M:%S UTC; path=/", &gmt);

	// Prepare output chain
	out = ngx_alloc_chain_link(r->pool);
	if (out == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to allocate %l bytes for buffer chain.", sizeof(ngx_chain_t));
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Prepare output buffer
	if ((buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to allocate %l bytes for response buffer.", sizeof(ngx_buf_t));
		return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	// Prepare output chain; hook the buffer
	out->buf = buf;
	out->next = NULL; 

	// Set the buffer
	buf->pos = (u_char *) cookie;
	buf->last = (u_char *) cookie + strlen(cookie);
	buf->mmap = 1; 
	buf->last_buf = 1; 

	// Status
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = buf->last - buf->pos;

	// Content-Type 
	r->headers_out.content_type.len = strlen(CONTENT_TYPE_T_P);
	r->headers_out.content_type.data = (u_char*) CONTENT_TYPE_T_P;

	ret = ngx_http_send_header(r);
	ret = ngx_http_output_filter(r, out);
	ngx_http_finalize_request(r, ret);
}

