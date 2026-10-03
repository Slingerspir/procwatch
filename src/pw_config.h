/* pw_config.h - option loading for the injected DLL.
 *
 * Options arrive from three places, in increasing priority:
 *   1. built-in defaults
 *   2. %TEMP%\ProcWatch\config.ini        (persistent, key=value lines)
 *   3. PROCWATCH_OPTS environment variable (set by the injector for children)
 *   4. %TEMP%\ProcWatch\pending.ini        (one-shot, used for PID injection)
 * Syntax everywhere is "key=value,key=value". */
#ifndef PW_CONFIG_H
#define PW_CONFIG_H

#include "pw_common.h"

void pw_config_defaults(PW_CONFIG *cfg);
void pw_config_parse(PW_CONFIG *cfg, const char *kv);
void pw_config_load(PW_CONFIG *cfg);

/* Render the effective configuration as a comma separated string. */
void pw_config_to_string(const PW_CONFIG *cfg, char *out, int outsz);

/* Persist the current options so future injections inherit them. */
int  pw_config_save_default(const PW_CONFIG *cfg);

/* Write a one-shot pending.ini for a PID injection. */
int  pw_config_write_pending(const PW_CONFIG *cfg);

#endif /* PW_CONFIG_H */
