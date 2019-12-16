#ifndef NGX_NNBC_NETMAP_H
#define NGX_NNBC_NETMAP_H

typedef struct nnbc_netaddr_s nnbc_netaddr_t;
struct nnbc_netaddr_s {
  long len;
  char *addr;
  char *mask;
};
// addr = the address;
// len = the length of the address
// x = the nnbc_netaddr object the address is being compared to
//
// match = (len == x.len);  <-- the address cannot match the network
//                              if the address lengths differ
// for(i=0; match && i<x.len; i++) {
//   if((addr[i]&x.mask[i]) != x.addr[i]) {
//     match = false;
//   }
// }


/**
 * Return 0 on success, non-zero on failure. (A failure would be if
 * the buffer were not large enough to hold the netaddr.)
 */
int nnbc_netaddr_to_string(nnbc_netaddr_t *addr, char *buffer, uint buffersize);


/**
 * Return 0 on success, non-zero on failure.
 */
int parse_netlist_config(ngx_array_t **array, ngx_str_t *comma_separated_list, ngx_pool_t *pool, ngx_log_t *log);

/**
 * Return 1 if the addr (expressed as an ngx string)
 * is in the net, 0 if it is not in the net.
 */
int is_in_net(nnbc_netaddr_t *net, char *addr, int len, ngx_log_t *log);

/**
 * Return 1 (true) is the address is in one of the networks in the
 * array of netaddrs, 0 (false) if it is not.
 */
int is_in_array_of_nets(ngx_str_t* addr, ngx_array_t *array, ngx_log_t *log);


#endif
