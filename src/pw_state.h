/* pw_state.h - process-wide state and the event reporting entry point.
 *
 * pw_report() is the only function hooks call. It is allocation-free, never
 * touches a hooked API and is safe to call from any thread of the host.
 */
#ifndef PW_STATE_H
#define PW_STATE_H

#include "pw_common.h"
#include "pw_events.h"
#include "pw_config.h"

extern PW_CONFIG  g_cfg;
extern PW_LOG     g_log;
extern HMODULE    g_self;                     /* our own module, never hooked */
extern DWORD      g_pid;
extern char       g_exe_path[MAX_PATH];
extern char       g_exe_name[128];
extern char       g_user[64];
extern unsigned long long g_start_ms;
extern char       g_http_url[64];             /* "" when the server is off */

extern volatile long g_active;                /* 0 once the DLL is deactivated */
extern volatile long g_paused;                /* 1 = observe nothing, pass through */

void pw_state_init(void);

/* Re-entrancy guard. Internal threads (GUI, HTTP, log writer) set this so their
 * own file/socket traffic is not reported as activity of the target. Calling a
 * hooked API from inside a hook is likewise suppressed. */
void pw_suppress_init(void);
void pw_suppress_enter(void);
void pw_suppress_leave(void);
int  pw_suppressed(void);

/* Build, classify and append one event. Returns the sequence number, or 0 when
 * the event was dropped (paused, suppressed, deactivated). */
unsigned long long pw_report(int cat, int lvl, const char *api,
                             const char *target, const char *detail,
                             unsigned int size, int result);

/* Same, but ignores the suppression flag. Used for our own lifecycle events
 * ("monitor attached", "hooks installed") which must always be visible. */
unsigned long long pw_report_force(int cat, int lvl, const char *api,
                                   const char *target, const char *detail,
                                   unsigned int size, int result);

/* Human readable module/level names. */
const char *pw_cat_name(int cat);
const char *pw_lvl_name(int lvl);

/* Startup diagnostics written straight to
 * %TEMP%\ProcWatch\trace-<pid>.log, flushed per line.
 *
 * An injected DLL has nowhere to print: stdout belongs to the host, and if
 * something goes wrong during hook installation the process is often gone
 * before anything else can be observed. This file is the only reliable record
 * of how far initialisation got. It is only written during startup. */
void pw_trace(const char *fmt, ...);

#endif /* PW_STATE_H */
