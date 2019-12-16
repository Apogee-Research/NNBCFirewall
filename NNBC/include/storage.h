#ifndef STORAGE_H
#define STORAGE_H

/**
 * Increment the number of accesses for the specified address. Fill
 * the t1_score and t2_score parameters with the associated db
 * columns.
 *
 * Return 0 on success, 1 if the entry does not exist, -1 on error.
 */
int get_scores(char* address, float t2_threshold, float* t1_score, float* t2_score);

/**
 * Return 0 on success, 1 if the entry does not exist, -1 on error.
 */
int
add_to_misbehavior(char* address, int misbehave_value, float* t1_score, float* t2_score);


int initialize_new_client(char* address, float t1_score, float t2_score, float t2_access_multiplier);


/**
 * Increment the number of connections for the specified address. Fill
 * the t1_score and t2_score parameters with the associated db
 * columns.
 *
 * Return 0 on success, 1 if the entry does not exist, -1 on error.
 */
int increment_connections(char* address, float* t1_score, float* t2_score);

/**
 * Decrement the number of connections for the specified address.
 *
 * Return 0 on success, 1 if the entry does not exist, -1 on error.
 */
int decrement_connections(char* address);

/**
 * Clear all connections; done on startup.
 *
 * Return 0 on success, -1 on error.
 */
int clear_connections(void);


#endif
