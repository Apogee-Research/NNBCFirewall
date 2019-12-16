#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nnbc.h"
#include "storage.h"
#include "subscribers.h"
#include "globals.h"
#include "netmap.h"
#include "parse_config.h"

float t1_threshold;
float t2_threshold;
int VERBOSE;
int under_attack;
float t1_epsilon;
float t1_attack_epsilon;
float t2_epsilon;
float t2_attack_epsilon;
float t2_initial_access_multiplier;
char *dbname;
char *dbuser;
char *dbpass;
char *sensor_channel;
char *t1_threshold_channel;
char *t2_threshold_channel;

int
start_threads()
{
  __attribute__((unused)) pthread_t thread_id;

  thread_id = pthread_create(&thread_id, NULL, &under_attack_listener, NULL);
  thread_id = pthread_create(&thread_id, NULL, &t1_thresholds_listener, NULL);
  thread_id = pthread_create(&thread_id, NULL, &t2_thresholds_listener, NULL);
  return 0;
}

/**
 * Return 0 on success, non-zero on error
 */
int
initialize_nnbc(const char* config_file)
{
  if (parse_config(config_file)) {
    fprintf(stderr, "parse_config failed with file <%s>\n", config_file);
    return -1;
  }
  if (start_threads()) {
    fprintf(stderr, "launch_threads failed!");
    return -1;
  }
  if (clear_connections()) {
    fprintf(stderr, "First try at clear_connections failed; sleep one second and try again.\n");
    sleep(1);
    if (clear_connections()) {
      fprintf(stderr, "Second try at clear_connections failed; getting on with it.\n");
    }
  }
  return 0;
}

/*
int
enable_streaming(void)
{
  int fd = open("/tmp/NNBC_COUNT_CONNECTIONS", O_CREAT, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    perror("Failed to open/create '/tmp/NNBC_COUNT_CONNECTIONS'");
    return -1;
  }
  close(fd);
  return 0;
}
*/

int
nnbc_is_in_whitelist(const char *addr, int len)
{
  char address[len+1];
  memcpy(address, addr, len);
  address[len] = '\0';
  return netmap_is_in_whitelist(address);
}

int
nnbc_is_in_proxylist(const char *addr, int len)
{
  char address[len+1];
  memcpy(address, addr, len);
  address[len] = '\0';
  return netmap_is_in_proxylist(address);
}

static void
create_entry(char *address, float* t1_score, float* t2_score)
{
    if (VERBOSE) {
      fprintf(stderr, "client <%s> not in yet in database, adding now\n", address);
    }
    if (under_attack) {
      *t1_score = t1_threshold + t1_attack_epsilon;
      *t2_score = t2_threshold + t2_attack_epsilon;
    } else {
      *t1_score = t1_threshold + t1_epsilon;
      *t2_score = 0.0f;
    }
    if (*t1_score > 0) {
      *t1_score = 0;
    }
    if (*t2_score > 0) {
      *t2_score = 0;
    }
    if (initialize_new_client(address, *t1_score, *t2_score, t2_initial_access_multiplier)) {
      fprintf(stderr, "failed to add client <%s> to database\n", address);
    }
}

/**
 * Return 0 if the client is granted access.
 * Return 1 if the client is blocked at the first tier.
 * Return 2 if the client is blocked at the second tier.
 */
int
nnbc_get_bin(const char *id, int len)
{
  char address[len+1];
  memcpy(address, id, len);
  address[len] = '\0';
  
  float t1_score, t2_score;
  int i = get_scores(address, t2_threshold, &t1_score, &t2_score);
  if (i == 1) {
    create_entry(address, &t1_score, &t2_score);
  }
  int result = 0;
  if (t1_score < t1_threshold && t2_score > t2_threshold) {
    result = 1;
  } else if (t2_score < t2_threshold) {
    result = 2;
  }
  if (VERBOSE) {
    fprintf(stderr, "Entry: <%s>, t1_score: %.2f, t2_score: %.2f, nnbc_get_bin result: %d\n", address, t1_score, t2_score, result);
  }
  return result;
}

/**
 * Indicate that the client has misbehaved.
 * Args:
 *	weight  the amount of the misbehavior. zero is a no-op.
 *	id	the identity of the client that misbehaved.
 *	len	the length of the identity, not including the terminating nil.
 */
void
nnbc_misbehaved(int weight, const char *id, int len)
{
  char address[len+1];
  memcpy(address, id, len);
  address[len] = '\0';
  float t1_score, t2_score;
  int i = add_to_misbehavior(address, weight, &t1_score, &t2_score);
  if (i == 1) {
    create_entry(address, &t1_score, &t2_score);
    add_to_misbehavior(address, weight, &t1_score, &t2_score);
  }
}


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
int
nnbc_connecting(const char *id, int len)
{
  char address[len+1];
  memcpy(address, id, len);
  address[len] = '\0';
  
  float t1_score, t2_score;
  int i = increment_connections(address, &t1_score, &t2_score);
  if (i == 1) {
    create_entry(address, &t1_score, &t2_score);
  }
  int result = 0;
  if (t1_score < t1_threshold && t2_score > t2_threshold) {
    result = 1;
  } else if (t2_score < t2_threshold) {
    result = 2;
  }
  if (VERBOSE) {
    fprintf(stderr, "Entry: <%s>, t1_score: %.2f, t2_score: %.2f, nnbc_connecting result: %d\n", address, t1_score, t2_score, result);
  }
  return result;
}

/**
 * Invoked by software that is tracking client connections (see
 * nnbc_connected() above). Every client that has nnbc_connecting
 * invoked for it must also have nnbc_disconnected invoked--and the
 * same id must be passed.
 */
void
nnbc_disconnected(const char *id, int len)
{
  char address[len+1];
  memcpy(address, id, len);
  address[len] = '\0';
  
  decrement_connections(address);
  return;
}
