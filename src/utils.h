/**
 * Nginx Sobek module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

// Prototypes
void sobek_debug(char *format, ...);
char *memstr(char *haystack, char *needle, int64_t size);
char *from_ngx_str(ngx_pool_t *pool, ngx_str_t ngx_str);
char *from_ngx_str_malloc(ngx_pool_t *pool, ngx_str_t ngx_str);
int64_t get_trimmed_int(char *in);
char *trim_quotes(ngx_http_request_t *r, char *s);
void base16_encode(unsigned char *in, int len, char *out);
settings_t *get_settings(ngx_http_request_t *r);
ngx_int_t create_signature(ngx_http_request_t *r, time_t timestamp, char *challenge, int challenge_length, char *signature);


