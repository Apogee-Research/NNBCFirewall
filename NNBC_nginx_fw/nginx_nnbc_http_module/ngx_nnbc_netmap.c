// TODO:
//   Verify that no address has 1-bits where the netmask is 0.


#include <nginx.h>
#include <ngx_core.h>

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>

#include "ngx_nnbc_netmap.h"

static int
fill_entry(nnbc_netaddr_t *entry, char* addr_str, ngx_pool_t *pool, ngx_log_t *log)
{
  long mask_size = -1;
  char* mask_str = NULL;
  char saved_entry_string[256];

  if (addr_str == NULL) {
    ngx_log_error(NGX_LOG_ERR, log, 0, "In fill_entry with a NULL addr_str.");
    return 1;
  }
  mask_str = index(addr_str, '/');
  strncpy(saved_entry_string, addr_str, 256);
  saved_entry_string[255] = '\0';
  ngx_log_error(NGX_LOG_DEBUG, log, 0, "Parsing <%s> into an entry.", addr_str);
  if (mask_str) {
    *mask_str++ = '\0';
    errno = 0;
    mask_size = strtol(mask_str, NULL, 10);
    if (errno) {
      fprintf(stderr, "Failure to parse the mask from netaddress <%s>.\n", saved_entry_string);
      return 1;
    }
  }
  if (index(addr_str, ':')) {
    entry->len = 16;
    entry->addr = ngx_pnalloc(pool, 16);
    inet_pton(AF_INET6, addr_str, entry->addr);
  }
  if (index(addr_str, '.')) {
    entry->len = 4;
    entry->addr = ngx_pnalloc(pool, 4);
    inet_pton(AF_INET, addr_str, entry->addr);
  }
  entry->mask = ngx_pnalloc(pool, entry->len);
  memset(entry->mask, 0, entry->len);
  if (mask_size == -1) {
    for(int i=0; i<entry->len; i++) {
      entry->mask[i] = 0xff;
    }
  } else {
    int i=0;
    while(mask_size > 8) {
      entry->mask[i++] = 0xff;
      mask_size -= 8;
    }
    if (mask_size != 0) {
      char m = 0;
      while(mask_size > 0) {
        m = (m << 1)|0x1;
        mask_size -= 1;
      }
      entry->mask[i] = m;
    }
  }
  int mask_is_bad = 0;
  for(int i=0; i<entry->len; i++) {
    if (entry->addr[i] & (~entry->mask[i])) {
      mask_is_bad = 1;
      break;
    }
  }
  if (mask_is_bad) {
    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "Parsing <%s>, the address has non-zero bits where the mask is zero.",
                  addr_str);
    return 1;
  }
  nnbc_netaddr_to_string(entry, saved_entry_string, 256);
  ngx_log_error(NGX_LOG_DEBUG, log, 0,
                "Parsing <%s> into netaddr <%s>.",
                addr_str, saved_entry_string);
  return 0;
}

int
nnbc_netaddr_to_string(nnbc_netaddr_t *addr, char *buffer, uint buffersize)
{
  int addr_type = 0;

  if (buffersize < 20) {
    snprintf(buffer, buffersize, "Bfr2small");
    return 1;
  }

  if (addr->len == 0) {
    strncpy(buffer, "0:<no addr>/<no mask>", buffersize);
    return 0;
  }

  if (addr->len == 16) {
    addr_type = AF_INET6;
  }  if (addr->len == 4) {
    addr_type = AF_INET;
  }

  char *ptr = &(buffer[strlen(buffer)]);
  inet_ntop(addr_type, addr->addr, ptr, buffersize - strlen(buffer));

  if (!addr->mask) {
    return 0;
  }

  if (strlen(buffer) >= buffersize-2) {
    return 1;
  }
  ptr = &(buffer[strlen(buffer)]);
  strcpy(ptr++, "/");
  *ptr = '\0';
  int mask_count = 0;
  for(int i=0; i<addr->len; i++) {
    switch(0x0ff & addr->mask[i]) {
    case 255:
      mask_count += 8;
      break;
    case 127:
      mask_count += 7;
      break;
    case 63:
      mask_count += 6;
      break;
    case 31:
      mask_count += 5;
      break;
    case 15:
      mask_count += 4;
      break;
    case 7:
      mask_count += 3;
      break;
    case 3:
      mask_count += 2;
      break;
    case 1:
      mask_count += 1;
      break;
    }
    if ((0x0ff & addr->mask[i]) != 255) {
      break;
    }
  }
  snprintf(ptr, buffersize-strlen(buffer), "%d", mask_count);
  return 0;
}

static void
free_array(ngx_array_t *array, ngx_pool_t *pool)
{
  nnbc_netaddr_t* addrs = array->elts;
  for(uint i=0; i<array->nelts; i++) {
    if (addrs[i].addr) {
      ngx_pfree(pool, addrs[i].addr);
      addrs[i].addr = NULL;
    }
    if (addrs[i].mask) {
      ngx_pfree(pool, addrs[i].mask);
      addrs[i].mask = NULL;
    }
  }
  ngx_array_destroy(array);
}


/**
 * Return 0 on success, non-zero on failure.
 */
int
parse_netlist_config(ngx_array_t **array, ngx_str_t *comma_separated_list, ngx_pool_t *pool, ngx_log_t *log)
{
  char* param_string = NULL;
  char* token_string;
  char* tokenizer;
  int count;
  int result = 0;

  ngx_log_error(NGX_LOG_DEBUG, log, 0, "Entered <%s>", __FUNCTION__);
  if (comma_separated_list->len == 0) {
    count = 0;
    ngx_log_error(NGX_LOG_DEBUG, log, 0, "The list of netaddrs is an empty string.");
    goto build_array;
  }
  param_string = ngx_palloc(pool, comma_separated_list->len + 1);
  if (param_string == NULL) {
    return 1;
  }
  memcpy(param_string, comma_separated_list->data, comma_separated_list->len);
  param_string[comma_separated_list->len] = '\0';

  ngx_log_error(NGX_LOG_DEBUG, log, 0, "Parsing netlist configuration <%s>", param_string);

  for(count = 1, tokenizer = index(param_string, ','); tokenizer != NULL; tokenizer = index(tokenizer, ',')) {
    count++;
    tokenizer++;
  }
  ngx_log_error(NGX_LOG_DEBUG, log, 0, "Counted %d commas.", count);
  token_string = strtok_r(param_string, ",", &tokenizer);
  fprintf(stderr, "token_string = %p\n", token_string);
  if (token_string) {
    fprintf(stderr, "*token_string = %s\n", token_string);
  }

 build_array:
  *array = ngx_array_create(pool, count, sizeof(nnbc_netaddr_t));
  for(int i=0; token_string && i<count; i++) {
    nnbc_netaddr_t *entry = ngx_array_push(*array);
    if (entry == NULL) {
      ngx_log_error(NGX_LOG_ERR, log, 0, "Entry %d in the netaddr array is NULL.", i);
      result = 1;
      goto out;
    }
    if (fill_entry(entry, token_string, pool, log)) {
      result = 1;
      goto out;
    }
    token_string = strtok_r(NULL, ",", &tokenizer);
    fprintf(stderr, "token_string = %p\n", token_string);
    if (token_string) {
      fprintf(stderr, "*token_string = %s\n", token_string);
    }
  }
 out:
  ngx_pfree(pool, param_string);
  if (result) {
    free_array(*array, pool);
    *array = NULL;
  }
  return result;
}

/**
 * Return 1 if the addr (expressed as an array of bytes with length)
 * is in the net, 0 if it is not in the net.
 */
int
is_in_net(nnbc_netaddr_t *net, char *addr, int len, ngx_log_t *log)
{
  // Initialize match to TRUE if the lengths are equal, false
  // otherwise
  int match = (len == net->len);
  // Loop until match is false or all bytes have been compared
  for(int i=0; match && i < len; i++) {
    // Mask both sides with 0xff to avoid problems with sign
    // extension of numbers over 127.
    if ((addr[i] & net->mask[i] & 0xff) != (net->addr[i] & 0xff)) {
      match = 0;
    }
  }
  return match;
}

/**
 * Return 1 (true) is the address is in one of the networks in the
 * array of netaddrs, 0 (false) if it is not.
 */
int
is_in_array_of_nets(ngx_str_t *addr, ngx_array_t *array, ngx_log_t *log)
{
  char address_bytes[16]; // large enough for IPv5
  char address_string[120];
  int len = 0;
  
  memcpy(address_string, addr->data, addr->len);
  address_string[addr->len] = '\0';
  if (index(address_string, ':')) {
    len = 16;
    if (!inet_pton(AF_INET6, address_string, (void *)address_bytes)) {
      // ERROR! Not an IPv6 address
    }
  } else if (index(address_string, '.')) {
    len = 4;
    if (!inet_pton(AF_INET, address_string, (void *)address_bytes)) {
      // ERROR! Not an IPv4 address
    }
  } else {
    // ERROR! Neither ipv4 nor ipv6
  }

  nnbc_netaddr_t *nets = (nnbc_netaddr_t*)array->elts;
  for(ngx_uint_t i=0; i<array->nelts; i++) {
    if (is_in_net(&(nets[i]), address_bytes, len, log )) {
      return 1;
    }
  }
  return 0;
}

