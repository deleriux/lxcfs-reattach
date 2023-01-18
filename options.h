#ifndef _OPTIONS_H_
#define _OPTIONS_H_
#include <stdlib.h>
#include "common.h"

void options_parse(int argc, char **argv);
void options_destroy(void);
int options_have_name(const char *needle);
int options_verbose(void);
int options_dry(void);
int options_monitor(void);
pid_t options_pid(void);
#endif
