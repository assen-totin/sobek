/**
 * Nginx Sobek module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

#include "common.h"
#include "ngx_http_sobek_module.h"
#include "http.h"
#include "utils.h"

/**
 * Module initialisation
 */
ngx_int_t ngx_http_sobek_module_init (ngx_cycle_t *cycle) {
	ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Sobek module initialised");
	return NGX_OK;
}

/**
 * Module termination
 */
void ngx_http_sobek_module_end(ngx_cycle_t *cycle) {
	ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Sobek module ended");
}

/**
 * Create location configuration
 */
void* ngx_http_sobek_create_loc_conf(ngx_conf_t* cf) {
	ngx_http_sobek_loc_conf_t *loc_conf;

	if ((loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sobek_loc_conf_t))) == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Failed to allocate %l bytes for location config.", sizeof(ngx_http_sobek_loc_conf_t));
		return NGX_CONF_ERROR;
	}

	loc_conf->cookie_ttl = NGX_CONF_UNSET;
	loc_conf->challenge_length = NGX_CONF_UNSET;
	loc_conf->challenge_ttl = NGX_CONF_UNSET;

	return loc_conf;
}

/**
 * Merge location configuration
 */
char* ngx_http_sobek_merge_loc_conf(ngx_conf_t* cf, void* void_parent, void* void_child) {
	ngx_http_sobek_loc_conf_t *parent = void_parent;
	ngx_http_sobek_loc_conf_t *child = void_child;

	ngx_conf_merge_str_value(child->sign_key, parent->sign_key, DEFAULT_SIGN_KEY);
	ngx_conf_merge_str_value(child->cookie_name, parent->cookie_name, DEFAULT_COOKIE_NAME);
	ngx_conf_merge_sec_value(child->cookie_ttl, parent->cookie_ttl, DEFAULT_COOKIE_TTL);
	ngx_conf_merge_uint_value(child->challenge_length, parent->challenge_length, DEFAULT_CHALLENGE_LENGTH);
	ngx_conf_merge_sec_value(child->challenge_ttl, parent->challenge_ttl, DEFAULT_CHALLENGE_TTL);

	if ((child->challenge_length < 32) || (child->challenge_length < 1024)) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Chalenge length must be between 32 and 1024"); 
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

/**
 * Init module and set handler
 */
char *ngx_http_sobek_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_core_loc_conf_t  *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_sobek_handler;

	return NGX_CONF_OK;
}

/**
 * Content handler
 */
ngx_int_t ngx_http_sobek_handler(ngx_http_request_t *r) {
	ngx_int_t ret;

	// POST set callback and return
	if (r->method & (NGX_HTTP_POST)) {
		// Set body handler
		if ((ret = ngx_http_read_client_request_body(r, sobek_handler_post)) >= NGX_HTTP_SPECIAL_RESPONSE)
			return ret;

		return NGX_DONE;
	}

	// GET and HEAD
	if (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))
		return sobek_handler_get(r);

	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "HTTP method not supported: %l", r->method);
	return NGX_ERROR;
} 

