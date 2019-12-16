#ifndef NNBC_H
#define NNBC_H

/**
 * Initialize the library. Must be run in each process, as threads are launched.
 *
 * config_file  The pathname of the configuration to load.
 * streaming    Non-zero if the streaming module is being loaded.
 *
 * Return 0 on success, non-zero on error
 */
int initialize_nnbc(const char* config_file);

/**
 * Indicate that the client has misbehaved.
 * Args:
 *	weight  the amount of the misbehavior. zero is a no-op.
 *	id	the identity of the client that misbehaved.
 *	len	the length of the identity, not including the terminating nil.
 */
void nnbc_misbehaved(int weight, const char *id, int len);

/**
 * Invoked by software checking transactional access (e.g., a web request).
 *
 * Return 0 if the client is granted access.
 * Return 1 if the client is blocked at the first tier.
 * Return 2 if the client is blocked at the second tier.
 */
int nnbc_get_bin(const char *id, int len);

/**
 * Invoked by software that is checking connection access (i.e.,
 * whether or not a socket is allowed). If software invokes this
 * method, it MUST invoke disconnected() when the client terminates
 * the connection, else the client will be associated with too many
 * connections.
 *
 * Return 0 if the client is granted access.
 * Return 1 if the client is blocked at the first tier.
 * Return 2 if the client is blocked at the second tier.
 */
int nnbc_connecting(const char *id, int len);

/**
 * Invoked by software that is tracking client connections (see
 * nnbc_connected() above). Every client that has nnbc_connecting
 * invoked for it must also have nnbc_disconnected invoked--and the
 * same id must be passed.
 */
void nnbc_disconnected(const char *id, int len);

int nnbc_is_in_whitelist(const char *addr, int len);

int nnbc_is_in_proxylist(const char *addr, int len);


#endif
