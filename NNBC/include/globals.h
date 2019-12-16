#ifndef GLOBALS_H
#define GLOBALS_H

extern float t1_threshold;
extern float t2_threshold;

extern float t1_epsilon;
extern float t1_attack_epsilon;
extern float t2_epsilon;
extern float t2_attack_epsilon;

extern float t2_initial_access_multiplier;

extern char *sensor_channel;
extern char *t1_threshold_channel;
extern char *t2_threshold_channel;

extern char *dbname;
extern char *dbuser;
extern char *dbpass;

extern int under_attack;
extern int VERBOSE;

#endif
