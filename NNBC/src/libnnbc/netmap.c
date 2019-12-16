#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#include "netmap.h"
#include "globals.h"

struct address_s {
  int length;
  char mask[16];
  char address[16];
};
typedef struct address_s address_t;

static address_t *whitelist;
static int whitelist_len = 0;
static address_t *proxylist;
static int proxylist_len = 0;

static int netaddr_to_string(address_t *addr, char *buffer, uint buffersize);
static int fill_entry(address_t *entry, char* addr_str);
static int parse_netlist_config(address_t **array, int *array_len, char *comma_separated_list);
static int is_in_net(address_t *net, char *addr, int len);
static int is_in_array_of_nets(char *address_string, address_t *array, int array_len);


static int
fill_entry(address_t *entry, char* addr_str)
{
  long mask_size = -1;
  char* mask_str = NULL;
  char saved_entry_string[256];

  memset(entry, 0, sizeof(address_t));
  if (addr_str == NULL) {
    return 1;
  }
  mask_str = index(addr_str, '/');
  strncpy(saved_entry_string, addr_str, 256);
  saved_entry_string[255] = '\0';
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
    entry->length = 16;
    inet_pton(AF_INET6, addr_str, entry->address);
  }
  if (index(addr_str, '.')) {
    entry->length = 4;
    inet_pton(AF_INET, addr_str, entry->address);
  }
  if (mask_size == -1) {
    for(int i=0; i<entry->length; i++) {
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
  for(int i=0; i<entry->length; i++) {
    if (entry->address[i] & (~entry->mask[i])) {
      mask_is_bad = 1;
      break;
    }
  }
  if (mask_is_bad) {
    fprintf(stderr,
            "Parsing <%s>, the address has non-zero bits where the mask is zero.",
            addr_str);
    memset(entry, 0, sizeof(address_t));
    return 1;
  }
  netaddr_to_string(entry, saved_entry_string, 256);
  if (VERBOSE) fprintf(stderr, "Parsed <%s> into netaddr <%s>.", addr_str, saved_entry_string);
  return 0;
}

static int
netaddr_to_string(address_t *addr, char *buffer, uint buffersize)
{
  int addr_type = 0;

  if (buffersize < 20) {
    snprintf(buffer, buffersize, "Bfr2small");
    return 1;
  }

  if (addr->length == 0) {
    strncpy(buffer, "0:<no addr>/<no mask>", buffersize);
    return 0;
  }

  if (addr->length == 16) {
    addr_type = AF_INET6;
  } else if (addr->length == 4) {
    addr_type = AF_INET;
  } else {
    snprintf(buffer, buffersize, "BadLength");
    return 1;
  }

  inet_ntop(addr_type, addr->address, buffer, buffersize);

  if (strlen(buffer) >= buffersize-2) {
    return 1;
  }
  char *ptr = &(buffer[strlen(buffer)]);
  strcpy(ptr++, "/");
  *ptr = '\0';
  int mask_count = 0;
  for(int i=0; i<addr->length; i++) {
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


/**
 * Return 0 on success, non-zero on failure.
 */
static int
parse_netlist_config(address_t **array, int *array_len, char *comma_separated_list)
{
  char* param_string = NULL;
  char* token_string;
  char* tokenizer;
  int count;
  int result = 0;

  if (comma_separated_list == NULL || comma_separated_list[0] == '\0') {
    count = 0;
    goto build_array;
  }
  param_string = malloc(strlen(comma_separated_list)+1);
  strcpy(param_string, comma_separated_list);

  for(count = 1, tokenizer = index(param_string, ','); tokenizer != NULL; tokenizer = index(tokenizer, ',')) {
    count++;
    tokenizer++;
  }
  token_string = strtok_r(param_string, ",", &tokenizer);

 build_array:
  *array_len = count;
  *array = calloc(count, sizeof(address_t));
  for(int i=0; token_string && i<count; i++) {
    address_t *entry = &((*array)[i]);
    if (fill_entry(entry, token_string)) {
      result = 1;
      goto out;
    }
    token_string = strtok_r(NULL, ",", &tokenizer);
  }
 out:
  free(param_string);
  if (result) {
    free(*array);
    *array = NULL;
  }
  return result;
}

int
set_whitelist(char* config)
{
  return parse_netlist_config(&whitelist, &whitelist_len, config);
}

int
set_proxylist(char* config)
{
  return parse_netlist_config(&proxylist, &proxylist_len, config);
}


/**
 * Return 1 if the addr (expressed as an array of bytes with length)
 * is in the net, 0 if it is not in the net.
 */
static int
is_in_net(address_t *net, char *addr, int len)
{
  // Initialize match to TRUE if the lengths are equal, false
  // otherwise
  int match = (len == net->length);
  // Loop until match is false or all bytes have been compared
  for(int i=0; match && i < len; i++) {
    // Mask both sides with 0xff to avoid problems with sign
    // extension of numbers over 127.
    if ((addr[i] & net->mask[i] & 0xff) != (net->address[i] & 0xff)) {
      match = 0;
      break;
    }
  }
  return match;
}

/**
 * Return 1 (true) is the address is in one of the networks in the
 * array of netaddrs, 0 (false) if it is not.
 */
static int
is_in_array_of_nets(char *address_string, address_t *array, int array_len)
{
  char address_bytes[16]; // large enough for IPv5
  int len = 0;
  
  memset(address_bytes, 0, sizeof(address_bytes));
  if (index(address_string, ':')) {
    len = 16;
    if (!inet_pton(AF_INET6, address_string, (void *)address_bytes)) {
      fprintf(stderr, "Address <%s> has a colon but is not an IPv6 address.\n", address_string);
      return 0;
    }
  } else if (index(address_string, '.')) {
    len = 4;
    if (!inet_pton(AF_INET, address_string, (void *)address_bytes)) {
      fprintf(stderr, "Address <%s> has a period but is not an IPv4 address.\n", address_string);
      return 0;
    }
  } else {
    fprintf(stderr, "Address <%s> has a neither a period nor a colon, so is neither an IPv4 or an IPv6 address.\n", address_string);
    return 0;
  }

  for(int i=0; i<array_len; i++) {
    if (is_in_net(&(array[i]), address_bytes, len)) {
      return 1;
    }
  }
  return 0;
}

int
netmap_is_in_whitelist(char *address_string)
{
  return is_in_array_of_nets(address_string, whitelist, whitelist_len);
}

int
netmap_is_in_proxylist(char *address_string)
{
  return is_in_array_of_nets(address_string, proxylist, proxylist_len);
}
