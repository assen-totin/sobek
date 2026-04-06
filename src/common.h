/**
 * Nginx Sobek module
 *
 * @author: Assen Totin assen.totin@gmail.com
 */

//// PRE-INCLUDES

#define __USE_XOPEN
#define _GNU_SOURCE

//// INCLUDES

#include <errno.h>
#include <features.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

// RHEL 10 or newer
#if __GLIBC_MINOR__ == 39
	#define RHEL10
#endif

//// DEFINITIONS

#define CHALLENGE_LENGTH 64
#define CHALLENGE_TTL 60
#define CONTENT_TYPE_A_J "application/json"
#define CONTENT_TYPE_A_XWFU "application/x-www-form-urlencoded"
#define CONTENT_TYPE_T_P "text/plain"
#define DEFAULT_COOKIE_NAME "sobek"
#define DEFAULT_COOKIE_TTL 604800
#define DEFAULT_SIGN_KEY "12345678901234567890123456789012"
#define ERROR_MESSAGE_LENGTH 1024
#define HASH_LENGTH 32
#define SIGNATURE_LENGTH 32

// STRUCTURES

// Main config
typedef struct {
	ngx_array_t loc_confs; 		// ngx_http_sobek_conf_t
} ngx_http_sobek_main_conf_t;

// Local config
typedef struct {
	ngx_str_t sign_key;
} ngx_http_sobek_loc_conf_t;

// Globals
typedef struct {
	bool init;
	char *sign_key;
	char *cookie_name;
	time_t cookie_ttl;
} globals_t;

//// ENUMERATORS

//// GLOBALS
//extern globals_t *globals;

