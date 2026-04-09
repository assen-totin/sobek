/**
 * Nginx Sobek module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// Prototypes
ngx_int_t ngx_http_sobek_handler(ngx_http_request_t *r);
char *ngx_http_sobek_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
void* ngx_http_sobek_create_loc_conf(ngx_conf_t* cf);
char* ngx_http_sobek_merge_loc_conf(ngx_conf_t* cf, void* void_parent, void* void_child);
ngx_int_t ngx_http_sobek_module_init (ngx_cycle_t *cycle);
void ngx_http_sobek_module_end (ngx_cycle_t *cycle);

// Globals: array to specify how to handle configuration directives.
static ngx_command_t ngx_http_sobek_commands[] = {
	{
		ngx_string("sobek"),
		NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
		ngx_http_sobek_init,
		0,
		0,
		NULL
	},
	{
		ngx_string("sobek_sign_key"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_sobek_loc_conf_t, sign_key),
		NULL
	},
	{
		ngx_string("sobek_cookie_name"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_sobek_loc_conf_t, cookie_name),
		NULL
	},
	{
		ngx_string("sobek_cookie_ttl"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_sec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_sobek_loc_conf_t, cookie_ttl),
		NULL
	},
	{
		ngx_string("sobek_challenge_length"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_sobek_loc_conf_t, challenge_length),
		NULL
	},
	{
		ngx_string("sobek_challenge_ttl"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_sec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_sobek_loc_conf_t, challenge_ttl),
		NULL
	},
	ngx_null_command
};

// Globals: module context
static ngx_http_module_t ngx_http_sobek_module_ctx = {
	NULL,							// pre-configuration
	NULL,							// post-configuration
	NULL,							// allocations and initilizations of configurations for the main block configuration
	NULL,							// set the configuration based on the directives supplied in the configuration files
	NULL,							// allocations and initilizations of configurations for the server block configuration
	NULL,							// merge the server block configuration with the main block
	ngx_http_sobek_create_loc_conf,	// allocations and initilizations of configurations for the location block configuration
	ngx_http_sobek_merge_loc_conf		// callback to merge the location block configuration with the server block
};

// Globals: module definition
ngx_module_t ngx_http_sobek_module = {
	NGX_MODULE_V1,
	&ngx_http_sobek_module_ctx,	// pointer to be passed to calls made by NGINX API to your module
	ngx_http_sobek_commands,		// pointer to a struct with extra configuration directives used by the module
	NGX_HTTP_MODULE,			// type of module defined
	NULL,						// hook into the initialisation of the master process (not implemented)
	ngx_http_sobek_module_init,	// hook into the module initialisation phase; happens prior to master process forking
	NULL,						// hook into the module initialisation in new process phase; happens as the worker processes are forked.
	NULL,						// hook into the initialisation of threads (not implemented)
	NULL,						// hook into the termination of a thread (not implemented)
	NULL,						// hook into the termination of a child process, such as a worker process
	ngx_http_sobek_module_end,	// hook into the termination of the master process
	NGX_MODULE_V1_PADDING
};

