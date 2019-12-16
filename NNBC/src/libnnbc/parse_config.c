#include <yaml.h>
#include <stdlib.h>
#include <stdio.h>

#include "parse_config.h"
#include "netmap.h"
#include "globals.h"

#define GET_LONG_VALUE(a,b)   if (!strcmp(key, a)) { b = strtol(value, &endptr, 10); goto set_config_done; }
#define GET_FLOAT_VALUE(a,b)   if (!strcmp(key, a)) { b = strtod(value, &endptr); goto set_config_done; }
#define GET_STRING_VALUE(a,b)   if (!strcmp(key, a)) { b = malloc(strlen(value)+1); strcpy(b, value); goto set_config_done; }
#define GET_ARRAY_STRING_VALUE(a,b)   if (!strcmp(key, a)) { b = malloc(strlen(value)+1); strcpy(b, value); }

void set_config_value(char* key, char* value) {
  char *endptr = NULL;
  char *array_string = NULL;

  if (VERBOSE) fprintf(stderr, "Parsing key=%s, value=%s\n", key ? key : "NULL", value ? value : "NULL");
  GET_LONG_VALUE("verbose", VERBOSE);
  GET_FLOAT_VALUE("t1_epsilon", t1_epsilon);
  GET_FLOAT_VALUE("t1_attack_epsilon", t1_attack_epsilon);
  GET_FLOAT_VALUE("t2_epsilon", t2_epsilon);
  GET_FLOAT_VALUE("t2_attack_epsilon", t2_attack_epsilon);
  GET_FLOAT_VALUE("t2_initial_access_multiplier", t2_initial_access_multiplier);
  GET_STRING_VALUE("under_attack_channel", sensor_channel);
  GET_STRING_VALUE("t1_threshold_channel", t1_threshold_channel);
  GET_STRING_VALUE("t2_threshold_channel", t2_threshold_channel);
  GET_STRING_VALUE("dbname", dbname);
  GET_STRING_VALUE("user", dbuser);
  GET_STRING_VALUE("password", dbpass);

  GET_ARRAY_STRING_VALUE("whitelist", array_string);
  if (array_string) {
    set_whitelist(array_string);
    free(array_string);
    array_string = NULL;
    goto set_config_done;
  }
  GET_ARRAY_STRING_VALUE("proxylist", array_string);
  if (array_string) {
    set_proxylist(array_string);
    free(array_string);
    array_string = NULL;
    goto set_config_done;
  }
  
  return;
 set_config_done:
  if (endptr && endptr == value) {
    fprintf(stderr, "Failure to parse the value for configuration item %s\n", key);
    exit(-1);
  }
}

int
parse_config(const char *filename)
{
  // Assign default values
  t1_threshold = -10.0f;	// This is not a configuration value
  t2_threshold = -5.0f;		// This is not a configuration value
  t1_epsilon = 9.9f;
  t1_attack_epsilon = -0.5f;
  t2_epsilon = 4.9f;
  t2_attack_epsilon = 4.9f;
  t2_initial_access_multiplier = 0.1f;
  
  sensor_channel = NULL;
  t1_threshold_channel = NULL;
  t2_threshold_channel = NULL;
  dbname = NULL;
  dbuser = NULL;
  dbpass = NULL;
  
  under_attack = 0;		// This is not a configuration value
  VERBOSE = 0;

  FILE *file;
  yaml_parser_t parser;
  yaml_token_t token;
  int done = 0;
  
  int getting_key = 0;
  int getting_value = 0;

  char key[256];

  int result = 0;

  if (getenv("VERBOSE")) {
    VERBOSE = 1;
  }
  if (VERBOSE) printf("Parsing '%s'\n", filename);
  fflush(stdout);
  file = fopen(filename, "r");
  if (!file) {
    fprintf(stderr, "Failed to open %s as the input file.\n", filename);
    return -1;
  }
  if (!yaml_parser_initialize(&parser)) {
    fprintf(stderr, "Failed to initialize the yaml parser.\n");
    return -1;
  }
  yaml_parser_set_input_file(&parser, file);
  while (!done && !result) {
    int naming_the_block = 0;

    //if (VERBOSE) puts("About to scan");
    if (!yaml_parser_scan(&parser, &token)) {
      fprintf(stderr, "Failed to parser_scan the yaml.\n");
      return -1;
      break;
    }
    //if (VERBOSE) puts("Scanned");
    switch(token.type) {
      /* Stream start/end */
    case YAML_STREAM_START_TOKEN:
      //if (VERBOSE) puts("STREAM START");
      break;
    case YAML_STREAM_END_TOKEN:
      //if (VERBOSE) puts("STREAM END");
      done = 1;
      break;
      /* Token types (read before actual token) */
    case YAML_KEY_TOKEN:
      //if (VERBOSE) printf("(Key token)   ");
      getting_key = 1;
      break;
    case YAML_VALUE_TOKEN:
      //if (VERBOSE) printf("(Value token) ");
      getting_value = 1;
      break;
      /* Block delimeters */
    case YAML_BLOCK_SEQUENCE_START_TOKEN:
      //if (VERBOSE) puts("<b>Start Block (Sequence)</b>");
      naming_the_block = 1;
      break;
    case YAML_BLOCK_ENTRY_TOKEN:
      //if (VERBOSE) puts("<b>Start Block (Entry)</b>");
      break;
    case YAML_BLOCK_END_TOKEN:
      //if (VERBOSE) puts("<b>End block</b>");
      break;
      /* Data */
    case YAML_BLOCK_MAPPING_START_TOKEN:
      //if (VERBOSE) puts("[Block mapping]");
      break;
    case YAML_SCALAR_TOKEN:
      //if (VERBOSE) printf("scalar %s \n", token.data.scalar.value);
      if (naming_the_block) {
        naming_the_block = 0;
      }
      if (getting_key) {
        getting_key = 0;
        if (token.data.scalar.length > sizeof(key)-1) {
          fprintf(stderr, "YAML error, key too long: %s\n", token.data.scalar.value);
          result = -1;
          break;
        }
        memcpy(key, token.data.scalar.value, token.data.scalar.length);
        key[token.data.scalar.length] = '\0';
      }
      if (getting_value) {
        char *value = malloc(token.data.scalar.length+1);
        getting_value = 0;
        if (!value) {
          fprintf(stderr, "YAML error, malloc failed, value=: %s\n", token.data.scalar.value);
          result = -1;
          break;
        }
        memcpy(value, token.data.scalar.value, token.data.scalar.length);
        value[token.data.scalar.length] = '\0';
        set_config_value(key, value);
        free(value);
      }
      break;
      /* Others */
    default:
      if (VERBOSE && 0) printf("Got token of type %d\n", token.type);
    }
    yaml_token_delete(&token);
  }
  yaml_parser_delete(&parser);
  fclose(file);
  return result;
}
