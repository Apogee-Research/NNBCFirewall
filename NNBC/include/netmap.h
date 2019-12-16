#ifndef NETMAP_H
#define NETMAP_H

int set_whitelist(char* config);

int set_proxylist(char* config);

int netmap_is_in_whitelist(char *address_string);

int netmap_is_in_proxylist(char *address_string);

#endif
