/* pw_state.c */
#include "pw_state.h"
#include "pw_util.h"
#include "pw_rules.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

PW_CONFIG  g_cfg;
PW_LOG     g_log;
HMODULE    g_self = NULL;
DWORD      g_pid = 0;
char       g_exe_path[MAX_PATH] = {0};
char       g_exe_name[128] = {0};
char       g_user[64] = {0};
unsigned long long g_start_ms = 0;
char       g_http_url[64] = {0};

volatile long g_active = 0;
volatile long g_paused = 0;

static DWORD g_tls = TLS_OUT_OF_INDEXES;

void pw_suppress_init(void)
{
    if (g_tls == TLS_OUT_OF_INDEXES)
        g_tls = TlsAlloc();
}

void pw_suppress_enter(void)
{
    if (g_tls == TLS_OUT_OF_INDEXES) return;
    {
        ULONG_PTR v = (ULONG_PTR)TlsGetValue(g_tls);
        TlsSetValue(g_tls, (LPVOID)(v + 1));
    }
}

void pw_suppress_leave(void)
{
    if (g_tls == TLS_OUT_OF_INDEXES) return;
    {
        ULONG_PTR v = (ULONG_PTR)TlsGetValue(g_tls);
        if (v > 0) TlsSetValue(g_tls, (LPVOID)(v - 1));
    }
}

int pw_suppressed(void)
{
    if (g_tls == TLS_OUT_OF_INDEXES) return 0;
    return TlsGetValue(g_tls) != NULL;
}

static const char *const CAT_NAMES[] = PW_CAT_NAMES;
static const char *const LVL_NAMES[] = PW_LVL_NAMES;

const char *pw_cat_name(int cat)
{
    if (cat < 0 || cat > PW_CAT_SYS) return "?";
    return CAT_NAMES[cat];
}

const char *pw_lvl_name(int lvl)
{
    if (lvl < 0 || lvl > PW_LVL_SUSPECT) return "?";
    return LVL_NAMES[lvl];
}

void pw_state_init(void)
{
    DWORD n;
    char *slash;

    g_pid = GetCurrentProcessId();
    g_start_ms = pw_now_ms();

    n = GetModuleFileNameA(NULL, g_exe_path, sizeof(g_exe_path));
    if (n == 0) pw_str_copy(g_exe_path, sizeof(g_exe_path), "?");
    g_exe_path[sizeof(g_exe_path) - 1] = 0;

    pw_str_copy(g_exe_name, sizeof(g_exe_name), pw_base_name(g_exe_path));

    n = GetEnvironmentVariableA("USERNAME", g_user, sizeof(g_user));
    if (n == 0) pw_str_copy(g_user, sizeof(g_user), "?");

    (void)slash;
}

static unsigned long long report_common(int cat, int lvl, const char *api,
                                        const char *target, const char *detail,
                                        unsigned int size, int result)
{
    PW_EVENT ev;

    memset(&ev, 0, sizeof(ev));
    ev.ts     = pw_now_ms();
    ev.tid    = GetCurrentThreadId();
    ev.cat    = (unsigned char)cat;
    ev.lvl    = (unsigned char)lvl;
    ev.size   = size;
    ev.result = result;
    pw_str_copy(ev.api, sizeof(ev.api), api);
    pw_str_copy(ev.target, sizeof(ev.target), target);
    pw_str_copy(ev.detail, sizeof(ev.detail), detail);

    if (g_cfg.risk && cat != PW_CAT_SYS)
        pw_rules_apply(&ev);

    return pw_log_append(&g_log, &ev);
}

unsigned long long pw_report(int cat, int lvl, const char *api,
                             const char *target, const char *detail,
                             unsigned int size, int result)
{
    if (!g_active || g_paused || pw_suppressed()) return 0;
    return report_common(cat, lvl, api, target, detail, size, result);
}

unsigned long long pw_report_force(int cat, int lvl, const char *api,
                                   const char *target, const char *detail,
                                   unsigned int size, int result)
{
    if (!g_active) return 0;
    return report_common(cat, lvl, api, target, detail, size, result);
}

/* ------------------------------------------------------------ startup trace */

static FILE         *g_trace_file = NULL;
static int           g_trace_tried = 0;
static CRITICAL_SECTION g_trace_cs;
static int           g_trace_cs_ready = 0;

void pw_trace(const char *fmt, ...)
{
    va_list ap;
    char line[1024];
    int n;

    if (!g_trace_cs_ready) {
        InitializeCriticalSection(&g_trace_cs);
        g_trace_cs_ready = 1;
    }
    EnterCriticalSection(&g_trace_cs);

    if (!g_trace_tried) {
        char dir[MAX_PATH], path[MAX_PATH];
        g_trace_tried = 1;
        pw_data_dir(dir, sizeof(dir));
        CreateDirectoryA(dir, NULL);
        _snprintf(path, sizeof(path), "%s\\trace-%lu.log", dir,
                  (unsigned long)GetCurrentProcessId());
        path[sizeof(path) - 1] = 0;
        g_trace_file = fopen(path, "wb");
    }

    if (g_trace_file) {
        n = snprintf(line, sizeof(line), "[%8llu] [tid %5lu] ", pw_now_ms(),
                     (unsigned long)GetCurrentThreadId());
        va_start(ap, fmt);
        n += vsnprintf(line + n, sizeof(line) - (size_t)n - 2, fmt, ap);
        va_end(ap);
        if (n > (int)sizeof(line) - 2) n = (int)sizeof(line) - 2;
        line[n++] = '\n';
        fwrite(line, 1, (size_t)n, g_trace_file);
        fflush(g_trace_file);
    }

    LeaveCriticalSection(&g_trace_cs);
}
