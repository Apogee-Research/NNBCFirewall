#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <nnbc.h>

#include "ngx_nnbc_netmap.h"

/**
 * Ask permission for each connection, ask permission for each request.
 *
 * 1. (DONE) On a connection, check to see if the connection is from a
 * proxy. If it is not from a proxy, add the connection. If connection
 * is forbidden, drop the connection. (This should go through #4).
 *
 * 2. (DONE) On a request, if the request is being proxied, add the connection
 * to the proxied client. (Note that multiple requests can come over a
 * single connection!) Then, whether the connection is proxied or not,
 * ask if access is allowed. (Note that, if the connection is
 * disallowed, there will still be an end-of-request event. I think.)
 *
 * 3. (DONE) At the end-of-request event, if the connection is proxied,
 * decrement the connection.
 *
 * 4. (DONE) At the close-connection event, if the connection is not proxied,
 * decrement the connection.
 */

// TODO List:
//
//   Change over to using the nnbc utilities for checking white list
//   and proxy list.
//
//   (DONE) Add a method for the end-of-request (the logging phase).
//
//   (DONE) Do the above four items.
//
//   Check that, when permission is denied, there is still an
//   end-of-request event.

// This variable has the same name as the ngx_addon_name
// in the "config" file.
ngx_module_t ngx_nnbc_http_module;

typedef struct {
  ngx_str_t nnbc_ff_header;		// The header used to identify the real client
  ngx_str_t nnbc_upstream_proxies;	// The addresses/subnets of allowed upstream proxies
  ngx_array_t *upstream_proxies_array;	// The upstream proxies, converted to an array of netaddrs
  ngx_str_t nnbc_whitelist;		// The addresses/subnets of white-listed hosts (sensors)
  ngx_array_t *whitelist_array;		// The white-listed hosts, converted to an array of netaddrs
  ngx_str_t nnbc_configfile;		// The name of the file that holds the libnnbc configuration
  ngx_str_t nnbc_T2_value;		// The HTTP return code to inform upstream proxies regarding a bad client
} nnbc_main_conf_t;

static char nnbc_config_filename[_POSIX_PATH_MAX];
static ngx_int_t T2_value = 573;

#define MAX(a,b)  ((a) > (b) ? (a) : (b))
#define MIN(a,b)  ((a) < (b) ? (a) : (b))

static void
set_ff_header(ngx_http_request_t *r, const ngx_str_t *FF_HEADER, ngx_str_t *client_id)
{
  ngx_table_elt_t *h;
  h = ngx_list_push(&r->headers_out.headers);
  h->hash = 1;
  // Assigning the contents of a source struct to a destination struct.
  h->key = *FF_HEADER;
  h->value = *client_id;
}

/**
 * Search the in-headers for the ff_header
 */
static ngx_str_t *
search_headers(ngx_http_request_t *r, const ngx_str_t *FF_HDR)
{
  ngx_list_part_t *part;
  ngx_table_elt_t *h;
  ngx_uint_t i;

  if (FF_HDR->data == NULL || FF_HDR->len == 0) {
    return NULL;
  }
  part = &r->headers_in.headers.part;
  h = part->elts;

  for (i = 0; ; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }

      part = part->next;
      h = part->elts;
      i = 0;
    }

    if (ngx_strncmp(h[i].key.data, FF_HDR->data, MAX(h[i].key.len,FF_HDR->len)) == 0) {
      return &(h[i].value);
    }
  }
  return NULL;
}

/**
 * See if a string is in an array of strings. If the array is at all
 * large, we should move to a more efficiently-searched data
 * structures (hash table, red-black tree). But, for just a handful of
 * strings, this is efficient enough.
 *
static ngx_int_t
is_in_array(ngx_str_t *string, ngx_array_t *array_of_strings)
{
  ngx_str_t* strings;

  // If the array_of_strings pointer is NULL, the string isn't in it!
  if (array_of_strings == NULL) {
    return 0;
  }
  strings = (ngx_str_t*)array_of_strings->elts;
  for(ngx_uint_t i=0; i<array_of_strings->nelts; i++) {
    // if the string equals a configured proxy, then it is a proxy
    if ((string->len == strings[i].len) &&
        !ngx_strncmp(string->data, strings[i].data, string->len)) {
      return 1;
    }
  }
  // the string did not match any member of the array_of_strings
  return 0;
}
*/

/**
 * Fetch the content. Does this reveal return codes?
 *
static ngx_int_t
ngx_nnbc_http_content_handler(ngx_http_request_t *r)
{
}
*/

/**
 * The request handler. This is where we perform access control.
 */
static ngx_int_t
ngx_nnbc_http_access_handler(ngx_http_request_t *r)
{
  char address[INET6_ADDRSTRLEN];
  ngx_connection_t *cxn;

  cxn = r->connection;
  //client_addr.sockaddr = cxn->sockaddr;
  //client_addr.socklen = cxn->socklen;
  //client_addr.name = cxn->addr_text;
  ngx_memcpy(address, cxn->addr_text.data, cxn->addr_text.len);
  address[cxn->addr_text.len] = '\0';


  // This appears to never be true...
  if (r->main->internal) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "r->main->internal is already non-zero");
    return NGX_DECLINED;
  }

  // Do we really need to set this? Obviously, combined with the above
  // if-statement, this module will never process the same request
  // twice. It is not obvious that that is a risk...
  r->main->internal = 1;

  // The main config is where we store the NNBC data, for now.
  //
  //TODO:
  // allow this to be in location configuration. Doesn't the location
  // config transparently default back up to the main?
  nnbc_main_conf_t *main_conf = ngx_http_get_module_main_conf(r, ngx_nnbc_http_module);

  // Initialize the client id to be the address from which the request
  // is being made, presented as text.
  ngx_str_t *client_id = &cxn->addr_text;

  char addr[40];
  memcpy(addr, client_id->data, client_id->len);
  addr[client_id->len] = '\0';
  
  // Did this request come from a proxy?
  //  ngx_int_t from_proxy = is_in_array(client_id, main_conf->upstream_proxies_array);
  ngx_int_t from_proxy = nnbc_is_in_proxylist((const char *)client_id->data, client_id->len);

  // If it is from a proxy, override the client id.
  if (from_proxy) {
    ngx_str_t *new_id = NULL;
    if (NULL == (new_id = search_headers(r, &main_conf->nnbc_ff_header))) {
      // ERROR! If the request came from a proxy, it _MUST_ have an
      // FF header, or else not be served.
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "Received a connection from proxy <%s> that did not contain a forwarded-from header <%s>.",
                    r->connection->addr_text.data,
                    (main_conf->nnbc_ff_header.data ? main_conf->nnbc_ff_header.data : (u_char *)"NULL")
                    );

      // Instead of service unavailable, do we want to redirect the
      // client to a page that explains why their request was not
      // satisfied? (You can't make a request directly from a proxy--it
      // has to come through the proxy from somewhere else, and the
      // forwarded-for header must be set.
      //
      // ngx_str_t *location = &main_conf->nnbc_request_from_proxy_error;
      // return redirect(r, location);
      //
      return NGX_HTTP_SERVICE_UNAVAILABLE;
    }
    client_id = new_id;
    // Update address to reflect the new identity
    memcpy(address, client_id->data, client_id->len);
    address[client_id->len] = '\0';

    r->connection->proxy_protocol_addr.data = ngx_pnalloc(r->connection->pool, client_id->len);

    if (r->connection->proxy_protocol_addr.data != NULL) {
      ngx_memcpy(r->connection->proxy_protocol_addr.data, client_id->data, client_id->len);
      r->connection->proxy_protocol_addr.len = client_id->len;
    }

    // We do not need to free new_id, as it is part of the ngx request
    // headers
  } else {
    set_ff_header(r, &(main_conf->nnbc_ff_header), client_id);
  }

  // If the client is in the white list, then let it though the firewall.
  if (nnbc_is_in_whitelist((const char *)client_id->data, client_id->len)) {
    // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
    // "The client <%s> is in the whitelist.\n", address);
    /*
     * It is counter-intuitive, but NGX_DECLINED is the nginx
     * ok-to-access result
     */
    return NGX_DECLINED;
  }

  /*
   * If this request is being proxied, we need to increment the
   * connection count for the proxied host. (This could not happen
   * when the connection was established, and for all we know, the
   * proxy is sharing the TCP socket across multiple requests.) We
   * don't care about the result, because we are going to do a
   * nnbc_get_bin no matter what.
   */
  if (from_proxy) {
    __attribute__((unused)) int cbin = nnbc_connecting((const char *)client_id->data, client_id->len);
  }
  
  int nnbc_bin = nnbc_get_bin((const char *)client_id->data, client_id->len);

  switch(nnbc_bin) {
  case 0:
    // It is counter-intuitive, but NGX_DECLINED is the nginx
    // ok-to-access result
    return NGX_DECLINED;

  case 1:
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "NNBC: blocked <%s> at T1", address);
    // A simple 405 response. Should we make this
    // NGX_HTTP_SERVICE_UNAVAILABLE, or allow the admin to specify the
    // value to be returned in this case?
    return NGX_HTTP_NOT_ALLOWED;

  case 2:
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "NNBC: blocked <%s> at T2", address);
    // A 573 response that tells an upstream proxy to block the client
    // for some period of time
    return T2_value;
  }

  // WHAT!? We only understand responses 0-2. Any higher response
  // indicates that libnnbc has been mis-configured. Write out
  // an error, but allow the client to access their request.
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Client <%s> received an NNBC 'bin' of <%d>; the understood range is [0,2]. Check your nginx.conf.",
                r->connection->addr_text.data, nnbc_bin
                );

  return NGX_DECLINED;
}

static const int malicious_status_weight = 1;
//static ngx_uint_t malicious_status[] = {400, 401, 403, 404, 405, 409, 411, 412, 413, 414, 416, 417, 429, 431, 451};
//static const ssize_t NUMBER_OF_MALICIOUS_STATUSES = sizeof(malicious_status)/sizeof(ngx_uint_t);

// This is experimental code. If one uncomments the conditional
// return, the plug-in will treat any http/https query that returns a
// 400-level status as being client misbehavior. For example, if an
// attacker is performing a password-guessing attack on your server,
// this feature will limit the rate at which the attacker can try
// passwords.
static ngx_int_t
is_malicious_status(ngx_uint_t status)
{
  // return (ngx_int_t)status >= 400;
  return 0;
}

/**
 * The end-of-request handler.
 */
static ngx_int_t
ngx_nnbc_http_EOReq_handler(ngx_http_request_t *r)
{
  ngx_connection_t *c;

  c = r->connection;
  // See the comments above the is_malicious_status function.
  if (is_malicious_status(r->headers_out.status)) {
    if (nnbc_is_in_proxylist((const char*)c->addr_text.data, c->addr_text.len)) {
      if (!nnbc_is_in_whitelist((const char *)c->proxy_protocol_addr.data, c->proxy_protocol_addr.len)) {
        nnbc_misbehaved(malicious_status_weight, (const char*)c->proxy_protocol_addr.data, c->proxy_protocol_addr.len);
      }
    } else {
      if (!nnbc_is_in_whitelist((const char *)c->addr_text.data, c->addr_text.len)) {
        nnbc_misbehaved(malicious_status_weight, (const char*)c->addr_text.data, c->addr_text.len);
      }
    }
  }

  if (nnbc_is_in_proxylist((const char*)c->addr_text.data, c->addr_text.len)) {
    if (!nnbc_is_in_whitelist((const char *)c->proxy_protocol_addr.data, c->proxy_protocol_addr.len)) {
      nnbc_disconnected((const char *)c->proxy_protocol_addr.data, c->proxy_protocol_addr.len);
    }
  }
  return NGX_DECLINED;
}


/*
static void*
server_init(ngx_conf_t *cf)
{
  //char buffer[200];
  //snprintf(buffer, sizeof(buffer), "We are initializing the server context\n");
  //puts(buffer);
  return NULL;
}

static void *
location_init(ngx_conf_t *cf)
{
  //char buffer[200];
  //snprintf(buffer, sizeof(buffer), "We are initializing the location context\n");
  //puts(buffer);
  return NULL;
}
*/
static char*
server_merge(ngx_conf_t *cf, void* parent, void* child)
{
  //char buffer[200];
  //snprintf(buffer, sizeof(buffer), "We are merging the server context\n");
  //puts(buffer);
  return NGX_CONF_OK;
}

static char*
location_merge(ngx_conf_t *cf, void* parent, void* child)
{
  //char buffer[200];
  //snprintf(buffer, sizeof(buffer), "We are merging the location context\n");
  //puts(buffer);
  return NGX_CONF_OK;
}


/**
 * Initialize the module. We add it as an access-phase handler.
 */
static ngx_int_t
ngx_nnbc_http_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;
  nnbc_main_conf_t *nnbc_conf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  nnbc_conf = ngx_http_conf_get_module_main_conf(cf, ngx_nnbc_http_module);

  // Add the NNBC access handler (ngx_nnbc_http_access_handler) to the
  // list of handlers that handle the access phase for main. Why not
  // to the location?  Presumably, ngx handles the location stuff
  // internally.
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_nnbc_http_access_handler;

  // Add the NNBC end-of-request handler (ngx_nnbc_http_EOReq_handler)
  // to the list of handlers that handle the log phase for main. Why
  // not to the location?  Presumably, ngx handles the location stuff
  // internally.
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_nnbc_http_EOReq_handler;

  // Create the upstream proxies array.
  parse_netlist_config(&(nnbc_conf->upstream_proxies_array), &(nnbc_conf->nnbc_upstream_proxies), cf->pool, cf->log);
  if (nnbc_conf->upstream_proxies_array == NULL) {
    return NGX_ERROR;
  }
  parse_netlist_config(&(nnbc_conf->whitelist_array),&(nnbc_conf->nnbc_whitelist), cf->pool, cf->log);
  if (nnbc_conf->whitelist_array == NULL) {
    return NGX_ERROR;
  }
  //split_and_load(&(nnbc_conf->upstream_proxies_array),&(nnbc_conf->nnbc_upstream_proxies), cf->pool);
  //split_and_load(&(nnbc_conf->whitelist_array),&(nnbc_conf->nnbc_whitelist), cf->pool);

  // Save the nnbc configuration filename in a static variable
  memcpy(nnbc_config_filename, nnbc_conf->nnbc_configfile.data,
         MIN(_POSIX_PATH_MAX, nnbc_conf->nnbc_configfile.len));
  nnbc_config_filename[MIN(_POSIX_PATH_MAX, nnbc_conf->nnbc_configfile.len)] = '\0';

  return NGX_OK;
}

// This is how we parse the configuration.
// Fields:
//  ngx_str_t nnbc_ff_header;
//  ngx_str_t nnbc_upstream_proxies;
//  ngx_str_t nnbc_whitelist;
//  ngx_uint_t nnbc_T2_return_value;
//
static ngx_command_t ngx_nnbc_http_commands[] = {
  {
    ngx_string("nnbc_ff_header"), 	// The client proxy header, defaults to "X-Forwarded-For"
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,	// Where the directive is found, how many args it has
    ngx_conf_set_str_slot,            	// How to set the value -- use the string function
    NGX_HTTP_MAIN_CONF_OFFSET,       	// No idea what that is
    offsetof(nnbc_main_conf_t, nnbc_ff_header), // The offset of the field in the config datastruct
    NULL
  },

  {
    ngx_string("nnbc_upstream_proxies"),// A list (array) of IP addresses
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,  // Where the directive is found, how many args it has
    ngx_conf_set_str_slot,      	// How to set the value
    NGX_HTTP_MAIN_CONF_OFFSET,        	// No idea what that is
    offsetof(nnbc_main_conf_t, nnbc_upstream_proxies), // The offset of the field in the config datastruct
    NULL
  },

  {
    ngx_string("nnbc_whitelist"),	// A list (array) of IP addresses
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,  // Where the directive is found, how many args it has
    ngx_conf_set_str_slot,      	// How to set the value
    NGX_HTTP_MAIN_CONF_OFFSET,        	// No idea what that is
    offsetof(nnbc_main_conf_t, nnbc_whitelist), // The offset of the field in the config datastruct
    NULL
  },

  {
    ngx_string("nnbc_configfile"),	// The name of the libnnbc config file
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,  // Where the directive is found, how many args it has
    ngx_conf_set_str_slot,      	// How to set the value
    NGX_HTTP_MAIN_CONF_OFFSET,        	// The method for deciding where to put the value
    offsetof(nnbc_main_conf_t, nnbc_configfile), // The offset of the field in the config datastruct
    NULL
  },

  {
    ngx_string("nnbc_T2_return_value"),	// An HTTP return value
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,  // Where the directive is found, how many args it has
    ngx_conf_set_str_slot,      	// How to set the value
    NGX_HTTP_MAIN_CONF_OFFSET,        	// The method for deciding where to put the value
    offsetof(nnbc_main_conf_t, nnbc_T2_value), // The offset of the field in the config datastruct
    NULL
  },

  ngx_null_command
};


static void*
ngx_nnbc_http_create_main_conf(ngx_conf_t *cf)
{
  nnbc_main_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(nnbc_main_conf_t));
  if (conf == NULL) {
    return NULL;
  }
  conf->nnbc_ff_header.data = NULL;
  conf->nnbc_upstream_proxies.data = NULL;
  conf->nnbc_whitelist.data = NULL;

  return conf;
}

/**
 * Never see this invoked.
 */
static ngx_int_t
nnbc_init_master(ngx_log_t *log)
{
  //pid_t pid = getpid();
  //ngx_log_error(NGX_LOG_ERR, log, 0, "nnbc_init_master invoked by process <%d>.\n", pid);
  return NGX_OK;
}

/**
 * Invoked by the process created on the command line.
 */
static ngx_int_t
nnbc_init_module(ngx_cycle_t *cycle)
{
  //pid_t pid = getpid();
  //ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "nnbc_init_module invoked by process <%d>.\n", pid);
  return NGX_OK;
}

static void
nnbc_init_connection(ngx_connection_t *c)
{
  //char buffer[264];
  char addr[64];
  if (c->addr_text.len < 64) {
    memcpy(addr, c->addr_text.data, c->addr_text.len);
    addr[c->addr_text.len] = '\0';
  } else {
    strcpy(addr, "Addr too long.");
  }
  if (!nnbc_is_in_whitelist((const char *)c->addr_text.data, c->addr_text.len) &&
      !nnbc_is_in_proxylist((const char *)c->addr_text.data, c->addr_text.len)) {
    int status = nnbc_connecting((const char *)c->addr_text.data, c->addr_text.len);
    if (status) {
      ngx_http_close_connection(c);
      return;
    }
  }
  ngx_http_init_connection(c);
}

static ngx_int_t
(*orig_del_conn)(ngx_connection_t *c, ngx_uint_t flags);

/**
 * Handles closing a connection.
 */
static ngx_int_t
nnbc_del_conn(ngx_connection_t *c, ngx_uint_t flags)
{
  char addr[64];
  char addr2[64];
  if (c->addr_text.len == 0) {
    return orig_del_conn(c, flags);
  }
  if (c->addr_text.len < 64) {
    memcpy(addr, c->addr_text.data, c->addr_text.len);
    addr[c->addr_text.len] = '\0';
  } else {
    strcpy(addr, "Addr too long.");
  }
  if (c->proxy_protocol_addr.data != NULL) {
    memcpy(addr2, c->proxy_protocol_addr.data, c->proxy_protocol_addr.len);
    addr2[c->proxy_protocol_addr.len] = '\0';
  } else {
    strcpy(addr2, "No Proxy");
  }

  ngx_int_t result = orig_del_conn(c, flags);
  if (!result) {
    if (!nnbc_is_in_proxylist((const char *)c->addr_text.data, c->addr_text.len)) {
      nnbc_disconnected((const char *)c->addr_text.data, c->addr_text.len);
    }
  }
  return result;
}


/**
 * Invoked by the daemon on startup.
 */
static ngx_int_t
nnbc_init_process(ngx_cycle_t *cycle)
{
  pid_t pid = getpid();
  ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "nnbc_init_process: process <%d> initializing libnnbc with config <%s>.",
                pid, nnbc_config_filename);

  //char buffer[200];
  ngx_listening_t *ls = cycle->listening.elts;
  for (uint i = 0; i < cycle->listening.nelts; i++) {
    if (ls[i].handler == &ngx_http_init_connection) {
      ls[i].handler = &nnbc_init_connection;
    }
  }
  if (ngx_event_actions.del_conn) {
    orig_del_conn = ngx_event_actions.del_conn;
    ngx_event_actions.del_conn = &nnbc_del_conn;
  }
  // TODO: instead of terminating the process when there is an error
  // parsing the configuration, initialize_nnbc should return a
  // non-zero result.
  int result = 0;
  result = initialize_nnbc(nnbc_config_filename);
  if (result) {
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                  "nnbc_init_process: an error occurred while initializing libnnbc with config <%s>.",
                  nnbc_config_filename);
    return NGX_ERROR;
  }    
  return NGX_OK;
}

static ngx_int_t
nnbc_init_thread(ngx_cycle_t *cycle)
{
  return NGX_OK;
}

// This is the structure of initialization functions. It
// is how a module describes itself--by how it is initialized.
//
// This module inintializes itself after the ngx configuration
// has been parsed. And, apparently, prior to the creation
// of the main configuration. Because magic.
// postconfiguration is when the module is loaded. So, we
// are doing initialization when (after) the module is
// loaded.
static ngx_http_module_t ngx_nnbc_http_module_ctx = {
  NULL,			                /* preconfiguration */
  ngx_nnbc_http_init,                   /* postconfiguration */
  ngx_nnbc_http_create_main_conf,       /* create main configuration */
  NULL,                                 /* init main configuration */
  NULL,                                 /* create server configuration */
  server_merge,                                 /* merge server configuration */
  NULL,                                 /* create location configuration */
  location_merge                                  /* merge location configuration */
};

// Initialize our module variable.
//
ngx_module_t ngx_nnbc_http_module = {
  NGX_MODULE_V1,
  &ngx_nnbc_http_module_ctx,     /* module context */
  ngx_nnbc_http_commands,        /* module directives */
  NGX_HTTP_MODULE,                 /* module type */
  nnbc_init_master,                            /* init master */
  nnbc_init_module,                            /* init module */
  nnbc_init_process,                            /* init process */
  nnbc_init_thread,                            /* init thread */
  NULL,                            /* exit thread */
  NULL,                            /* exit process */
  NULL,                            /* exit master */
  NGX_MODULE_V1_PADDING
};

