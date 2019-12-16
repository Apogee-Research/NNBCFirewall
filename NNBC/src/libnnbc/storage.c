#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <libpq-fe.h>
#include "globals.h"

char *connStrBase = "user=%s password=%s dbname=%s";


/*
  addr INET PRIMARY KEY
  t1_score float4
  t2_score float4
  t2_access_multiplier float4
  below_t2 BOOLEAN
  misbehaviors INT
  accesses INT
  connections INT
*/
/* Note that we are creating the entry with one access and one connection! */




static PGconn *
open_connection()
{
  int connStrLen = strlen(connStrBase) + 50;
  char connStr[connStrLen];
  snprintf(connStr, connStrLen, connStrBase, dbuser, dbpass, dbname);
  PGconn *conn = PQconnectdb(connStr);
  if (PQstatus(conn) == CONNECTION_BAD) {
    fprintf(stderr, "Connection to database failed. Tried with connection string:\n%s\nFailure message:\n%s\n", connStr, PQerrorMessage(conn));
    PQfinish(conn);
    return NULL;
  }
  return conn;
}

#define MAX_POOL_SIZE  64
static PGconn *freelist[MAX_POOL_SIZE];
static int freelist_index = 0;
static int pool_size = 0;

static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pool_cond = PTHREAD_COND_INITIALIZER;

#define FREELIST_IS_EMPTY 	(freelist_index == 0)
#define POP_FREELIST 		freelist[--freelist_index]
#define PUSH_FREELIST(a) 	freelist[freelist_index++] = a

static PGconn *
get_connection()
{
  PGconn *cxn = NULL;
  pthread_mutex_lock(&pool_lock);
  if (FREELIST_IS_EMPTY) {
    if (pool_size < MAX_POOL_SIZE) {
      cxn = open_connection();
      if (cxn) {
        pool_size++;
      }
      goto OUT;
    }
    while(FREELIST_IS_EMPTY) {
      pthread_cond_wait(&pool_cond, &pool_lock);
    }
    cxn = POP_FREELIST;
    goto OUT;
  } else {
    cxn = POP_FREELIST;
  }
 OUT:
  pthread_mutex_unlock(&pool_lock);
  return cxn;
}

static void release_connection(PGconn *cxn)
{
  pthread_mutex_lock(&pool_lock);
  PUSH_FREELIST(cxn);
  pthread_cond_signal(&pool_cond);
  pthread_mutex_unlock(&pool_lock);
}

static int
modify_entry(char* query, float* t1_score, float* t2_score)
{
  PGconn *conn = get_connection();
  if (conn == NULL) {
    return -1;
  }
  int ret = 0;
  PGresult *res = PQexec(conn, query);
  if (PQresultStatus(res) == PGRES_TUPLES_OK) {
    // query was successful
    int num_returned = PQntuples(res);
    if (num_returned == 0) {
      // query didn't return any rows, this client not in DB
      ret = 1;
    } else if (num_returned == 1) {
      // query returned 1 row (expected)
      *t1_score = atof(PQgetvalue(res, 0, 0));
      *t2_score = atof(PQgetvalue(res, 0, 1));
    } else {
      // query returned multiple rows (unexpected, addr is primary key)
      ret = -1;
    }

  } else {
    // query failed
    fprintf(stderr, "Query <%s> failed: %s\n", query, PQresultErrorMessage(res));
    ret = -1;
  }
  PQclear(res);
  release_connection(conn);
  return ret;
}

/**
 * Return 0 on success, 1 if the entry does not exist, -1 on error.
 */
const char *GET_SCORES_QUERY =
  "UPDATE nnbc_clients SET accesses = accesses + 1, t2_blocked = t2_blocked or t2_score < %f WHERE addr = '%s' RETURNING t1_score, t2_score";
int
get_scores(char* address, float t2_threshold, float* t1_score, float* t2_score)
{
  int qlen = strlen(GET_SCORES_QUERY) + 100;
  char query[qlen];
  snprintf(query, qlen, GET_SCORES_QUERY, t2_threshold, address);
  return modify_entry(query, t1_score, t2_score);
}

/**
 * Return 0 on success, 1 if the entry does not exist, -1 on error.
 */
const char *ADD_TO_MISBEHAVIOR =
  "UPDATE nnbc_clients SET misbehaviors = misbehaviors + %d WHERE addr = '%s' RETURNING t1_score, t2_score";
int
add_to_misbehavior(char* address, int misbehave_value, float* t1_score, float* t2_score)
{
  int qlen = strlen(ADD_TO_MISBEHAVIOR) + 100;
  char query[qlen];
  snprintf(query, qlen, ADD_TO_MISBEHAVIOR, misbehave_value, address);
  return modify_entry(query, t1_score, t2_score);
}


/**
 * Return 0 on success, 1 if the entry does not exist, -1 on error.
 */
const char *INCREMENT_CONNECTIONS =
  "UPDATE nnbc_clients SET connections = connections + 1 WHERE addr = '%s' RETURNING t1_score, t2_score";
int
increment_connections(char* address, float* t1_score, float* t2_score)
{
  int qlen = strlen(INCREMENT_CONNECTIONS) + 100;
  char query[qlen];
  snprintf(query, qlen, INCREMENT_CONNECTIONS, address);
  return modify_entry(query, t1_score, t2_score);
}

/**
 * Return 0 on success, 1 if the entry does not exist, -1 on error.
 */
const char *DECREMENT_CONNECTIONS =
  "UPDATE nnbc_clients SET connections = (CASE WHEN connections > 0 THEN connections - 1 ELSE 0 END) WHERE addr = '%s' RETURNING t1_score, t2_score";
int
decrement_connections(char* address)
{
  float t1_score;
  float t2_score;
  int qlen = strlen(DECREMENT_CONNECTIONS) + 100;
  char query[qlen];
  snprintf(query, qlen, DECREMENT_CONNECTIONS, address);
  return modify_entry(query, &t1_score, &t2_score);
}


/**
 * Return 0 on success, -1 on error.
 */
const char *CLEAR_CONNECTIONS = "UPDATE nnbc_clients SET connections = 0";
int
clear_connections(void)
{
  PGconn *conn = get_connection();
  if (conn == NULL) {
    return -1;
  }
  int ret = 0;
  PGresult *res = PQexec(conn, CLEAR_CONNECTIONS);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    fprintf(stderr, "Failed query: %s\n", PQresultErrorMessage(res));
    ret = -1;
  }
  PQclear(res);
  release_connection(conn);
  return ret;
}


/**
 * Return 0 on success, -1 on error.
 */
const char *INSERT_NEW_QUERY = "INSERT INTO nnbc_clients VALUES ('%s', %f, %f, %f, false, 0, 1, 1) ON CONFLICT (addr) DO NOTHING";
int
initialize_new_client(char* address, float t1_score, float t2_score, float t2_access_multiplier)
{
  int qlen = strlen(INSERT_NEW_QUERY) + 50;
  char query[qlen];
  snprintf(query, qlen, INSERT_NEW_QUERY, address, t1_score, t2_score, t2_access_multiplier);
  PGconn *conn = get_connection();
  if (conn == NULL) {
    return -1;
  }
  int ret = 0;
  PGresult *res = PQexec(conn, query);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    fprintf(stderr, "Failed query:\n%s\n%s\n", query, PQresultErrorMessage(res));
    ret = -1;
  }
  PQclear(res);
  release_connection(conn);
  return ret;
}
