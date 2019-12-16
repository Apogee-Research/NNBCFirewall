
#include <stdio.h>
#include <stdlib.h>
#include <hiredis/hiredis.h>
#include <errno.h>
#include <string.h>
#include "globals.h"

static int pubsub_subscribe(void (*callback_fn)(char*, int), char* channel) {
  redisContext *context_r = NULL;
  if (!(context_r = redisConnect("localhost", 6379)) || context_r->err) {
    fprintf(stderr, "ERROR, could not create Redis context. Error: %s\n",
            context_r?context_r->errstr:strerror(errno));
    return -1;
  }
  redisReply *reply = redisCommand(context_r, "SUBSCRIBE %s", channel);
  freeReplyObject(reply);
  while ( redisGetReply(context_r, (void**)(&reply)) == REDIS_OK ) {
    if (reply->type == REDIS_REPLY_ARRAY) {
      callback_fn(reply->element[2]->str, reply->element[2]->len);
    }
    freeReplyObject(reply);
  }
  return 0;
}

static void
t1_threshold_callback(char* buffer, __attribute__ ((unused)) int bufsize)
{
  t1_threshold = atof(buffer);
  if (VERBOSE > 1) {
    fprintf(stderr, "t1_threshold = %f\n", t1_threshold);
  }
}

static void
t2_threshold_callback(char* buffer, __attribute__ ((unused)) int bufsize)
{
  t2_threshold = atof(buffer);
  if (VERBOSE > 1) {
    fprintf(stderr, "t2_threshold = %f\n", t2_threshold);
  }
}

static void
under_attack_callback(char* buffer, __attribute__ ((unused)) int bufsize)
{
  under_attack = atoi(buffer);
  if (VERBOSE > 1) {
    fprintf(stderr, "under_attack = %d\n", under_attack);
  }
}

void*
t1_thresholds_listener(__attribute__ ((unused)) void *arg)
{
  pubsub_subscribe(&t1_threshold_callback, t1_threshold_channel);
  return NULL;
}

void*
t2_thresholds_listener(__attribute__ ((unused)) void *arg)
{
  pubsub_subscribe(&t2_threshold_callback, t2_threshold_channel);
  return NULL;
}

void*
under_attack_listener(__attribute__ ((unused)) void *arg)
{
  pubsub_subscribe(&under_attack_callback, sensor_channel);
  return NULL;
}
