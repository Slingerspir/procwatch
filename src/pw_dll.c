/* pw_dll.c - DllMain and the orchestration thread.
 *
 * DllMain does nothing but remember our module handle and spawn a thread: the
 * loader lock is held while DllMain runs, and starting threads, loading DLLs or
 * touching the registry from inside it is how injected DLLs deadlock. All real
 * work happens on the thread below, which also stays around as a watchdog. */
#include "pw_common.h"
#include "pw_state.h"
#include "pw_events.h"
#include "pw_config.h"
#include "pw_hooks.h"
#include "pw_gui.h"
#include "pw_http.h"
#include "pw_util.h"

#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HMODULE       g_dll_module = NULL;
static HANDLE        g_init_thread = NULL;
static volatile long g_shutdown = 0;
static FILE         *g_logfile = NULL;
static unsigned long long g_logfile_cursor = 0;

/* ------------------------------------------------------------- environment */

/* The proxy configuration the host is running under is context an analyst wants
 * before reading any request: report it once, at attach. Every API used here is
 * reached through our own (never patched) import table, and this thread holds
 * the suppression flag, so none of it is reported as target activity. */
static void report_environment(void)
{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG cfg;
    char buf[600];
    char env[512];
    DWORD n;

    memset(&cfg, 0, sizeof(cfg));
    if (WinHttpGetIEProxyConfigForCurrentUser(&cfg)) {
        char autoUrl[300] = {0}, proxy[300] = {0}, bypass[300] = {0};
        if (cfg.lpszAutoConfigUrl) pw_wide_to_utf8(cfg.lpszAutoConfigUrl, autoUrl, sizeof(autoUrl));
        if (cfg.lpszProxy)         pw_wide_to_utf8(cfg.lpszProxy, proxy, sizeof(proxy));
        if (cfg.lpszProxyBypass)   pw_wide_to_utf8(cfg.lpszProxyBypass, bypass, sizeof(bypass));

        _snprintf(buf, sizeof(buf),
                  "系统代理：%s%s%s%s%s%s",
                  proxy[0] ? proxy : "(未配置)",
                  bypass[0] ? "  绕过: " : "", bypass,
                  autoUrl[0] ? "  自动配置脚本: " : "", autoUrl,
                  cfg.fAutoDetect ? "  [自动检测已开启]" : "");
        buf[sizeof(buf) - 1] = 0;
        pw_report_force(PW_CAT_SYS, PW_LVL_INFO, "SystemProxy", g_exe_name, buf, 0, 0);

        if (cfg.lpszAutoConfigUrl) GlobalFree(cfg.lpszAutoConfigUrl);
        if (cfg.lpszProxy)         GlobalFree(cfg.lpszProxy);
        if (cfg.lpszProxyBypass)   GlobalFree(cfg.lpszProxyBypass);
    }

    n = GetEnvironmentVariableA("HTTP_PROXY", env, sizeof(env));
    if (n == 0 || n >= sizeof(env)) n = GetEnvironmentVariableA("http_proxy", env, sizeof(env));
    if (n > 0 && n < sizeof(env)) {
        _snprintf(buf, sizeof(buf), "环境变量 HTTP_PROXY = %s", env);
        buf[sizeof(buf) - 1] = 0;
        pw_report_force(PW_CAT_SYS, PW_LVL_INFO, "EnvProxy", g_exe_name, buf, 0, 0);
    }
    n = GetEnvironmentVariableA("HTTPS_PROXY", env, sizeof(env));
    if (n == 0 || n >= sizeof(env)) n = GetEnvironmentVariableA("https_proxy", env, sizeof(env));
    if (n > 0 && n < sizeof(env)) {
        _snprintf(buf, sizeof(buf), "环境变量 HTTPS_PROXY = %s", env);
        buf[sizeof(buf) - 1] = 0;
        pw_report_force(PW_CAT_SYS, PW_LVL_INFO, "EnvProxy", g_exe_name, buf, 0, 0);
    }
}

/* ------------------------------------------------------------------ log file */

static void open_logfile(void)
{
    char dir[MAX_PATH], logs[MAX_PATH], path[MAX_PATH];
    char ts[64];

    if (!g_cfg.log_file || g_logfile) return;

    pw_data_dir(dir, sizeof(dir));
    pw_path_join(logs, sizeof(logs), dir, "logs");
    CreateDirectoryA(dir, NULL);
    CreateDirectoryA(logs, NULL);

    pw_iso_str(pw_now_ms(), ts, sizeof(ts));
    {
        int i;
        for (i = 0; ts[i]; i++)
            if (ts[i] == ':' || ts[i] == ' ' || ts[i] == '.') ts[i] = '-';
    }
    _snprintf(path, sizeof(path), "%s\\%lu-%s-%s.jsonl", logs,
              (unsigned long)g_pid, g_exe_name, ts);
    path[sizeof(path) - 1] = 0;

    g_logfile = fopen(path, "wb");
    if (g_logfile) {
        char detail[400];
        _snprintf(detail, sizeof(detail), "事件同时写入文件：%s", path);
        detail[sizeof(detail) - 1] = 0;
        pw_report_force(PW_CAT_SYS, PW_LVL_INFO, "LogFile", g_exe_name, detail, 0, 0);
        g_logfile_cursor = pw_log_last_seq(&g_log);
    }
}

static void drain_logfile(void)
{
    PW_EVENT evs[128];
    unsigned int n, i;

    if (!g_logfile) return;
    for (;;) {
        unsigned long long last = 0;
        n = pw_log_since(&g_log, g_logfile_cursor, evs, 128, &last);
        if (n == 0) break;
        for (i = 0; i < n; i++) {
            char line[2200];
            int w = pw_event_json(&evs[i], (unsigned long)g_pid, line, sizeof(line));
            if (w > 0) {
                fputs(line, g_logfile);
                fputc('\n', g_logfile);
            }
        }
        g_logfile_cursor = evs[n - 1].seq;
        if (n < 128) break;
    }
    fflush(g_logfile);
}

/* Tell a waiting injector that instrumentation is live. The event only exists
 * when we were started by injector.exe; a DLL dropped in by other means just
 * finds nothing to open. */
static void signal_ready(void)
{
    char name[64];
    HANDLE ev;

    _snprintf(name, sizeof(name), PW_READY_EVENT_FMT, (unsigned long)g_pid);
    name[sizeof(name) - 1] = 0;
    ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, name);
    if (ev) {
        SetEvent(ev);
        CloseHandle(ev);
        pw_trace("ready event signalled");
    }
}

/* ------------------------------------------------------------------- thread */

static DWORD WINAPI init_thread(LPVOID param)
{
    int port = 0;
    unsigned long long lastScan = 0, lastDiscovery = 0;
    char banner[600];

    (void)param;

    pw_suppress_init();
    pw_suppress_enter();          /* from here on, our own work is invisible */

    pw_trace("init thread started");
    pw_state_init();
    pw_trace("state init: exe=%s pid=%lu", g_exe_path, (unsigned long)g_pid);
    pw_config_load(&g_cfg);
    pw_trace("config: gui=%d http=%d port=%d log=%d ring=%u",
             g_cfg.gui, g_cfg.http, g_cfg.port, g_cfg.log_file, g_cfg.ring);

    if (!pw_log_init(&g_log, g_cfg.ring)) return 0;
    pw_trace("event ring ready (%u slots)", pw_log_count(&g_log));

    g_active = 1;

    _snprintf(banner, sizeof(banner),
              "监控已附加：%s (PID %lu)，用户 %s，事件缓存 %u 条",
              g_exe_path, (unsigned long)g_pid, g_user, g_cfg.ring);
    banner[sizeof(banner) - 1] = 0;
    pw_report_force(PW_CAT_SYS, PW_LVL_INFO, "Attach", g_exe_name, banner, 0, 0);

    open_logfile();
    report_environment();
    pw_trace("environment reported");

    /* Rewrite the export tables of the core modules and the import tables of
     * everything already loaded. */
    pw_hookapi_init();
    pw_trace("installing hooks");
    pw_hooks_install();
    pw_trace("hooks installed");

    /* Only now is it safe for a suspended target to start running. */
    signal_ready();

    if (g_cfg.http) {
        port = pw_http_start();
        pw_trace("http start -> port %d", port);
        if (port) {
            pw_http_write_discovery();
            pw_trace("discovery file written");
        }
    }

    if (g_cfg.gui) {
        if (pw_gui_start()) {
            pw_trace("gui window created");
            pw_report_force(PW_CAT_SYS, PW_LVL_INFO, "GuiStart", g_exe_name,
                            "进程内监控窗口已创建（关闭窗口不影响后台采集）", 0, 0);
        } else {
            pw_trace("gui window NOT created");
            pw_report_force(PW_CAT_SYS, PW_LVL_WARN, "GuiStart", g_exe_name,
                            "无法创建窗口（该进程可能没有桌面访问权限），"
                            "请改用 WebUI", 0, 0);
        }
    }
    pw_trace("entering watchdog loop");

    /* Watchdog: drain the file mirror, refresh the discovery record and pick up
     * modules that appeared without going through our LoadLibrary hooks. */
    while (!g_shutdown) {
        unsigned long long now = pw_now_ms();

        drain_logfile();

        if (g_active && now - lastScan > 5000) {
            lastScan = now;
            pw_hooks_rescan();
        }
        if (now - lastDiscovery > 4000) {
            lastDiscovery = now;
            if (g_cfg.http && port) pw_http_write_discovery();
        }
        Sleep(500);
    }

    if (g_logfile) { drain_logfile(); fclose(g_logfile); g_logfile = NULL; }
    return 0;
}

/* ------------------------------------------------------------------- DllMain */

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_dll_module = (HMODULE)inst;
        g_self = (HMODULE)inst;
        DisableThreadLibraryCalls(inst);

        /* Nothing but a thread creation here: the loader lock is held. */
        g_init_thread = CreateThread(NULL, 0, init_thread, NULL, 0, NULL);
        if (g_init_thread) CloseHandle(g_init_thread);
        else pw_trace("DllMain: CreateThread failed (%lu)", (unsigned long)GetLastError());
        break;

    case DLL_PROCESS_DETACH:
        /* On process exit, or on FreeLibrary. Undoing the patches during
         * FreeLibrary is not safe while other threads may be inside our code,
         * so we only stop observing; /api/deactivate does the clean removal. */
        g_shutdown = 1;
        g_active = 0;
        pw_http_stop();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    default:
        break;
    }
    return TRUE;
}
