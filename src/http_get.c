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
	struct timeval tv;
	int res;
	unsigned int json_len;
	unsigned char *random;
	char *challenge = NULL, *json, *sig_b16;
	ngx_buf_t *buf = NULL;
	ngx_chain_t *out;
	ngx_int_t ret = NGX_OK;

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "GET processing request");

	// Get current timestamp
	if ((res = gettimeofday(&tv, NULL)) < 0) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to get current time: %s", strerror(errno));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get random & convert it to Base-16 challenge
	if ((random = ngx_pcalloc(r->pool, CHALLENGE_LENGTH)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to allocate %l bytes for random data.", CHALLENGE_LENGTH);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((res = RAND_bytes(random, CHALLENGE_LENGTH)) < 1) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to generate %l bytes of random data: %s", CHALLENGE_LENGTH, ERR_error_string(ERR_get_error(), NULL));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((challenge = ngx_pcalloc(r->pool, 2 * CHALLENGE_LENGTH + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to allocate %l bytes for challenge.", 2 * CHALLENGE_LENGTH + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	//base16_encode2(r, random, CHALLENGE_LENGTH, challenge);
	//base16_encode(random, CHALLENGE_LENGTH, challenge);
	int i;
	for (i=0; i < CHALLENGE_LENGTH; i++)
		sprintf(challenge + 2 * i, "%c%c", HEX[random[i] >> 4], HEX[random[i] & 0x0F]);

	// Prepare space for signature in Base-16
	if ((sig_b16 = ngx_pcalloc(r->pool, 2 * SIGNATURE_LENGTH + 1)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to allocate %l bytes for signature in Base-16.", 2 * SIGNATURE_LENGTH + 1);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get signature for challenge and timestamp
	if ((res = create_signature(r, tv.tv_sec, challenge, sig_b16)) > 0)
		return res;

	// Prepare output JSON
/*
{
"timestamp":1234567890,
"challenge":"abcdef...",
"signature":"0123456789abcdef..." 
}
*/
	json_len = 1 + 12 + 10 + 1 + 13 + 2 * CHALLENGE_LENGTH + 2 + 13 + 2 * SIGNATURE_LENGTH + 1 + 1 + 1;	
	if ((json = ngx_pcalloc(r->pool, json_len)) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to allocate %l bytes for JSON.", json_len);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "GET JSON length: %l", json_len - 1);

	strcpy(json, "{\"timestamp\":");
	sprintf(json + strlen(json), "%li", tv.tv_sec);
	strcpy(json + strlen(json), ",\"challenge\":\"");
	memcpy(json + strlen(json), challenge, 2 * CHALLENGE_LENGTH);
	strcpy(json + strlen(json), "\",\"signature\":\"");
	memcpy(json + strlen(json), sig_b16, 2 * SIGNATURE_LENGTH);
	strcpy(json + strlen(json), "\"}");
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "GET JSON: %s", json);

	// Prepare output chain
	out = ngx_alloc_chain_link(r->pool);
	if (out == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to allocate %l bytes for buffer chain.", sizeof(ngx_chain_t));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Prepare output buffer
	if ((buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "GET failed to allocate %l bytes for response buffer.", sizeof(ngx_buf_t));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	// Prepare output chain; hook the buffer
	out->buf = buf;
	out->next = NULL; 

	// Set the buffer
	buf->pos = (u_char *) json;
	buf->last = (u_char *) json + strlen(json);
	buf->memory = 1; 
	buf->last_buf = 1; 

	// Status
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = buf->last - buf->pos;

	// Content-Type 
	r->headers_out.content_type.len = strlen(CONTENT_TYPE_A_J);
	r->headers_out.content_type.data = (u_char*) CONTENT_TYPE_A_J;

	ret = ngx_http_send_header(r);
	ret = ngx_http_output_filter(r, out);
	//ngx_http_finalize_request(r, ret);

	return NGX_OK;
}

