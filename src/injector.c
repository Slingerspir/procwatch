/* pw_injector.c - loads ProcWatch.dll into a target process, and optionally
 * serves a hub page listing every instrumented process on this machine.
 *
 * Usage:
 *   injector.exe --exe <program> [args...]   launch suspended, inject, resume
 *   injector.exe --pid <pid>                 inject into a running process
 *   injector.exe --list                      list instrumented processes
 *   injector.exe --hub                       serve the hub page on port 8700
 *
 * Options (also forwarded to the DLL):
 *   --dll <path>     DLL to inject (default: ProcWatch.dll next to this exe)
 *   --gui=0|1        in-process monitoring window            (default 1)
 *   --http=0|1       embedded web server                     (default 1)
 *   --port=N         preferred WebUI port                    (default auto)
 *   --log=0|1        mirror events to a file                 (default 0)
 *   --previews=0|1   capture payload previews                (default 0)
 *   --risk=0|1       heuristic risk rules                    (default 1)
 *   --verbose=0|1    log high-frequency calls                (default 0)
 *   --ring=N         event ring capacity                     (default 8192)
 *
 * The DLL receives no arguments at injection time, so options travel either in
 * the child's environment (launch mode) or through a one-shot pending.ini that
 * the DLL consumes at startup (PID mode). */
#include "../src/pw_common.h"
#include "../src/pw_config.h"
#include "../src/pw_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shellapi.h>

#include "pw_hub_html.h"

static PW_CONFIG g_cfg;
static char      g_dllPath[MAX_PATH];
static int       g_verbose = 0;

/* ------------------------------------------------------------------ helpers */

static void err(const char *fmt, const char *a)
{
    char buf[900];
    _snprintf(buf, sizeof(buf), fmt, a ? a : "");
    buf[sizeof(buf) - 1] = 0;
    fprintf(stderr, "[!] %s (错误码 %lu)\n", buf, (unsigned long)GetLastError());
}

/* ------------------------------------------------------------------ elevation
 * A target whose manifest asks for administrator rights cannot be started (or
 * injected into) from a normal-integrity process: CreateProcess fails with
 * ERROR_ELEVATION_REQUIRED and OpenProcess on such a process fails with
 * ACCESS_DENIED. Neither is fixed by enabling SE_DEBUG - only elevation is.
 *
 * So on that failure we re-launch ourselves through the shell's "runas" verb,
 * forwarding our own command line verbatim, and step aside. The relaunched
 * instance gets a fresh console with the real output. */
#define PW_NO_ELEVATE_FLAG "--no-elevate"

static int already_elevated(void)
{
    HANDLE tok = NULL;
    TOKEN_ELEVATION el;
    DWORD n = 0;
    int elevated = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &n))
            elevated = el.TokenIsElevated ? 1 : 0;
        CloseHandle(tok);
    }
    return elevated;
}

/* Arguments after the program name, exactly as they were typed. */
static const char *raw_parameters(void)
{
    const char *cmd = GetCommandLineA();
    const char *p = cmd;
    if (!p) return "";
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        while (*p && *p != '"') p++;
        if (*p == '"') p++;
    } else {
        while (*p && *p != ' ' && *p != '\t') p++;
    }
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static void try_relaunch_elevated(void)
{
    char self[MAX_PATH * 2];
    char params[4096];
    SHELLEXECUTEINFOA sei;

    if (already_elevated()) return;

    if (!GetModuleFileNameA(NULL, self, sizeof(self))) return;
    _snprintf(params, sizeof(params), "%s %s", raw_parameters(), PW_NO_ELEVATE_FLAG);
    params[sizeof(params) - 1] = 0;

    printf("\n[*] 目标需要管理员权限，正在以管理员身份重新启动注入器…\n");
    printf("    （会弹出 UAC 提示；新窗口里会继续同样的操作）\n\n");

    memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = self;
    sei.lpParameters = params;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExA(&sei)) {
        DWORD e = GetLastError();
        if (e == ERROR_CANCELLED)
            fprintf(stderr, "[!] 已取消提权。请右键以管理员身份运行本程序后重试。\n");
        else
            fprintf(stderr, "[!] 提权启动失败（错误码 %lu）。请手动以管理员身份运行。\n",
                    (unsigned long)e);
        return;
    }
    if (sei.hProcess) CloseHandle(sei.hProcess);
    printf("[*] 已在新的管理员窗口中继续，本窗口退出。\n");
    exit(0);
}

/* ----------------------------------------------------------------- injection */

static int enable_debug_privilege(void)
{
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    int ok = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return 0;
    if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL) &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(tok);
    return ok;
}

/* Created before the injection so the DLL can signal "hooks are installed".
 * The name is derived from the target PID, which both sides know. */
static HANDLE create_ready_event(DWORD pid)
{
    char name[64];
    _snprintf(name, sizeof(name), PW_READY_EVENT_FMT, (unsigned long)pid);
    name[sizeof(name) - 1] = 0;
    return CreateEventA(NULL, TRUE, FALSE, name);
}

/* Returns 1 if the DLL reported that it finished installing its hooks. */
static int wait_ready(HANDLE ev, int timeoutMs)
{
    DWORD rc;
    if (!ev) return 0;
    rc = WaitForSingleObject(ev, (DWORD)timeoutMs);
    CloseHandle(ev);
    return rc == WAIT_OBJECT_0;
}

static int inject_into(DWORD pid, const char *dllFullPath)
{
    HANDLE proc, thread;
    LPVOID remote;
    SIZE_T len, written = 0;
    wchar_t wide[MAX_PATH * 2];
    HMODULE k32;
    FARPROC loadLib;
    DWORD exitCode = 0;
    int ok = 0;

    pw_utf8_to_wide(dllFullPath, wide, MAX_PATH * 2);
    len = (wcslen(wide) + 1) * sizeof(wchar_t);

    proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                       FALSE, pid);
    if (!proc) {
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED && !already_elevated())
            fprintf(stderr, "[!] 打开进程被拒绝。若目标是管理员权限或更高完整性级别，"
                            "本程序也必须以管理员身份运行。\n");
        else
            err("无法打开进程 %lu", NULL);
        return 0;
    }

    remote = VirtualAllocEx(proc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { err("目标进程内分配内存失败：%s", NULL); CloseHandle(proc); return 0; }

    if (!WriteProcessMemory(proc, remote, wide, len, &written) || written != len) {
        err("写入 DLL 路径失败：%s", NULL);
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        return 0;
    }

    k32 = GetModuleHandleA("kernel32.dll");
    loadLib = GetProcAddress(k32, "LoadLibraryW");
    if (!loadLib) { CloseHandle(proc); return 0; }

    thread = CreateRemoteThread(proc, NULL, 0,
                                (LPTHREAD_START_ROUTINE)(ULONG_PTR)loadLib,
                                remote, 0, NULL);
    if (!thread) {
        /* Some hardened processes (protected/PPL) refuse remote threads. */
        err("CreateRemoteThread 失败，目标进程可能受保护：%s", NULL);
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        return 0;
    }

    WaitForSingleObject(thread, 15000);
    GetExitCodeThread(thread, &exitCode);
    CloseHandle(thread);
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    CloseHandle(proc);

    if (exitCode != 0) ok = 1;
    else err("目标进程内 LoadLibrary 返回失败（位数不匹配或缺少依赖？）：%s", NULL);
    return ok;
}

/* -------------------------------------------------------------- discovery */

typedef struct {
    DWORD pid;
    char  exe[128];
    char  user[64];
    int   port;
    int   gui;
    unsigned long long startedMs;
    int   alive;
    long long events;
    long long suspect;
    long long uptimeMs;
} INSTANCE;

#define MAX_INSTANCES 64

/* Minimal HTTP GET against a loopback ProcWatch instance. The hub aggregates
 * server side so the browser never has to deal with cross-origin requests. */
static int http_get(int port, const char *path, int isPost, char *out, int outsz)
{
    SOCKET s;
    struct sockaddr_in addr;
    char req[512];
    int total = 0;
    DWORD timeout = 700;
    WSADATA wsa;

    out[0] = 0;

    /* Probing instances needs Winsock even when the hub is not running. */
    {
        static int wsaReady = 0;
        if (!wsaReady) {
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
            wsaReady = 1;
        }
    }

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((u_short)port);

    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return 0;
    }

    _snprintf(req, sizeof(req),
              "%s %s HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
              isPost ? "POST" : "GET", path);
    req[sizeof(req) - 1] = 0;
    if (send(s, req, (int)strlen(req), 0) <= 0) { closesocket(s); return 0; }

    for (;;) {
        int n = recv(s, out + total, outsz - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        if (total >= outsz - 1) break;
    }
    out[total] = 0;
    closesocket(s);
    return total > 0;
}

static const char *find_body(const char *resp)
{
    const char *p = strstr(resp, "\r\n\r\n");
    return p ? p + 4 : resp;
}

/* Note the long long: the DLL reports absolute millisecond timestamps, which do
 * not fit in a 32-bit long on Windows. */
static long long json_num(const char *json, const char *key, long long def)
{
    char pat[64];
    const char *p;
    _snprintf(pat, sizeof(pat), "\"%s\":", key);
    pat[sizeof(pat) - 1] = 0;
    p = strstr(json, pat);
    if (!p) return def;
    return _strtoi64(p + strlen(pat), NULL, 10);
}

static void json_str(const char *json, const char *key, char *out, int outsz)
{
    char pat[64];
    const char *p, *q;
    int n;

    out[0] = 0;
    _snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    pat[sizeof(pat) - 1] = 0;
    p = strstr(json, pat);
    if (!p) return;
    p += strlen(pat);
    q = strchr(p, '"');
    if (!q) return;
    n = (int)(q - p);
    if (n >= outsz) n = outsz - 1;
    memcpy(out, p, (size_t)n);
    out[n] = 0;
}

static int discover(INSTANCE *list, int cap)
{
    char dir[MAX_PATH], pattern[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    int n = 0;

    pw_data_dir(dir, sizeof(dir));
    pw_path_join(pattern, sizeof(pattern), dir, "*.json");
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    do {
        char path[MAX_PATH], meta[4096], stats[2048];
        char exe[128];
        FILE *f;
        long size;

        if (n >= cap) break;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        pw_path_join(path, sizeof(path), dir, fd.cFileName);
        f = fopen(path, "rb");
        if (!f) continue;
        size = (long)fread(meta, 1, sizeof(meta) - 1, f);
        fclose(f);
        if (size <= 0) continue;
        meta[size] = 0;

        memset(&list[n], 0, sizeof(list[n]));
        list[n].pid = (DWORD)json_num(meta, "pid", 0);
        list[n].port = (int)json_num(meta, "port", 0);
        list[n].gui = (int)json_num(meta, "gui", 0);
        list[n].startedMs = (unsigned long long)json_num(meta, "startedMs", 0);        json_str(meta, "exe", exe, sizeof(exe));
        pw_str_copy(list[n].exe, sizeof(list[n].exe), exe[0] ? exe : "(未知)");

        /* Is the instance still answering? */
        if (list[n].port > 0) {
            char path2[128];
            _snprintf(path2, sizeof(path2), "/api/meta");
            path2[sizeof(path2) - 1] = 0;
            if (http_get(list[n].port, path2, 0, stats, sizeof(stats))) {
                const char *body = find_body(stats);
                if (strstr(body, "\"pid\"")) {
                    list[n].alive = 1;
                    list[n].events = json_num(body, "events", 0);
                    list[n].suspect = json_num(body, "suspect", 0);
                    list[n].uptimeMs = json_num(body, "uptimeMs", 0);
                    json_str(body, "exe", exe, sizeof(exe));
                    if (exe[0]) pw_str_copy(list[n].exe, sizeof(list[n].exe), exe);
                }
            }
        }
        if (!list[n].alive) {
            /* Not answering: decide between "exited" and "crashed". */
            HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, list[n].pid);
            if (!p) {
                DeleteFileA(path);
                continue;                    /* gone for good - drop the record */
            }
            CloseHandle(p);
        }
        n++;
    } while (FindNextFileA(h, &fd));

    FindClose(h);
    return n;
}

/* ----------------------------------------------------------------- hub server */

static int  g_hubPort = 0;
static volatile long g_hubRunning = 0;

static void hub_send(int fd, const char *ctype, const char *body, int len)
{
    char head[512];
    int off = 0;
    _snprintf(head, sizeof(head),
              "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
              "Cache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\n"
              "Connection: close\r\n\r\n", ctype, len);
    head[sizeof(head) - 1] = 0;
    while (off < (int)strlen(head)) {
        int n = send(fd, head + off, (int)strlen(head) - off, 0);
        if (n <= 0) return;
        off += n;
    }
    off = 0;
    while (off < len) {
        int n = send(fd, body + off, len - off, 0);
        if (n <= 0) return;
        off += n;
    }
}

static void hub_list(int fd)
{
    INSTANCE list[MAX_INSTANCES];
    int n = discover(list, MAX_INSTANCES), i;
    char *buf = (char *)malloc(65536);
    int cap = 0;

    if (!buf) return;
    cap += snprintf(buf + cap, 65536 - (size_t)cap, "[");
    for (i = 0; i < n; i++) {
        cap += snprintf(buf + cap, 65536 - (size_t)cap,
                        "%s{\"pid\":%lu,\"exe\":\"%s\",\"port\":%d,\"gui\":%d,"
                        "\"startedMs\":%llu,\"alive\":%d,\"events\":%lld,"
                        "\"suspect\":%lld,\"uptimeMs\":%lld}",
                        i ? "," : "", (unsigned long)list[i].pid, list[i].exe,
                        list[i].port, list[i].gui, list[i].startedMs,
                        list[i].alive, list[i].events, list[i].suspect,
                        list[i].uptimeMs);
        if (cap > 63000) break;
    }
    cap += snprintf(buf + cap, 65536 - (size_t)cap, "]");
    hub_send(fd, "application/json; charset=utf-8", buf, cap);
    free(buf);
}

static void hub_action(int fd, const char *query, const char *action)
{
    INSTANCE list[MAX_INSTANCES];
    int n = discover(list, MAX_INSTANCES), i;
    long pid = (long)strtol(query, NULL, 10);
    int done = 0;

    /* The pid arrives as "?pid=123", so skip to the digits. */
    if (pid <= 0) {
        const char *eq = strchr(query, '=');
        if (eq) pid = strtol(eq + 1, NULL, 10);
    }

    for (i = 0; i < n; i++) {
        if ((long)list[i].pid != pid) continue;
        if (!strcmp(action, "deactivate")) {
            char resp[2048], path[64];
            _snprintf(path, sizeof(path), "/api/deactivate");
            path[sizeof(path) - 1] = 0;
            if (http_get(list[i].port, path, 1, resp, sizeof(resp))) done = 1;
        } else if (!strcmp(action, "forget")) {
            char dir[MAX_PATH], file[MAX_PATH];
            pw_data_dir(dir, sizeof(dir));
            _snprintf(file, sizeof(file), "%s\\%lu.json", dir, (unsigned long)pid);
            file[sizeof(file) - 1] = 0;
            DeleteFileA(file);
            done = 1;
        }
        break;
    }
    {
        char body[128];
        _snprintf(body, sizeof(body), "{\"ok\":%s,\"pid\":%ld}", done ? "true" : "false", pid);
        body[sizeof(body) - 1] = 0;
        hub_send(fd, "application/json; charset=utf-8", body, (int)strlen(body));
    }
}

static DWORD WINAPI hub_client(LPVOID param)
{
    int fd = (int)(INT_PTR)param;
    char req[4096];
    int got = recv(fd, req, sizeof(req) - 1, 0);

    if (got > 0) {
        char path[512] = {0}, query[256] = {0};
        req[got] = 0;
        {
            char *sp1 = strchr(req, ' ');
            char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
            if (sp1 && sp2) {
                char target[512];
                size_t tlen = (size_t)(sp2 - sp1 - 1);
                if (tlen >= sizeof(target)) tlen = sizeof(target) - 1;
                memcpy(target, sp1 + 1, tlen);
                target[tlen] = 0;
                {
                    char *qm = strchr(target, '?');
                    if (qm) {
                        size_t plen = (size_t)(qm - target);
                        if (plen >= sizeof(path)) plen = sizeof(path) - 1;
                        memcpy(path, target, plen);
                        path[plen] = 0;
                        pw_str_copy(query, sizeof(query), qm + 1);
                    } else {
                        pw_str_copy(path, sizeof(path), target);
                    }
                }
            }
        }

        if (!strcmp(path, "/") || !strcmp(path, "/index.html"))
            hub_send(fd, "text/html; charset=utf-8", (const char *)pw_hub_html,
                     (int)pw_hub_html_len);
        else if (!strcmp(path, "/api/list"))
            hub_list(fd);
        else if (!strcmp(path, "/api/deactivate"))
            hub_action(fd, query, "deactivate");
        else if (!strcmp(path, "/api/forget"))
            hub_action(fd, query, "forget");
        else {
            const char *nf = "not found";
            hub_send(fd, "text/plain", nf, (int)strlen(nf));
        }
    }
    closesocket(fd);
    return 0;
}

static DWORD WINAPI hub_server(LPVOID param)
{
    int fd = (int)(INT_PTR)param;
    while (g_hubRunning) {
        int c = accept(fd, NULL, NULL);
        if (c < 0) {
            if (!g_hubRunning) break;
            Sleep(50);
            continue;
        }
        {
            HANDLE t = CreateThread(NULL, 0, hub_client, (LPVOID)(INT_PTR)c, 0, NULL);
            if (t) CloseHandle(t);
            else closesocket(c);
        }
    }
    return 0;
}

static int hub_start(int port)
{
    int fd;
    struct sockaddr_in addr;
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
    fd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((u_short)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        closesocket(fd);
        return 0;
    }
    g_hubPort = port;
    g_hubRunning = 1;
    {
        HANDLE t = CreateThread(NULL, 0, hub_server, (LPVOID)(INT_PTR)fd, 0, NULL);
        if (t) CloseHandle(t);
    }
    return 1;
}

/* ------------------------------------------------------------------- output */

static void print_instances(void)
{
    INSTANCE list[MAX_INSTANCES];
    int n = discover(list, MAX_INSTANCES), i;

    if (!n) { printf("没有发现已注入 ProcWatch 的进程。\n"); return; }
    printf("%-8s %-28s %-7s %-10s %-9s %s\n", "PID", "进程", "端口", "事件", "可疑", "状态");
    printf("--------------------------------------------------------------------------\n");
    for (i = 0; i < n; i++) {
        char up[64];
        unsigned long long s = (list[i].uptimeMs ? (unsigned long long)list[i].uptimeMs : 0) / 1000;
        _snprintf(up, sizeof(up), "%llu时%llu分%llu秒", s / 3600, (s % 3600) / 60, s % 60);
        up[sizeof(up) - 1] = 0;
        printf("%-8lu %-28s %-7d %-10lld %-9lld %s  %s\n",
               (unsigned long)list[i].pid, list[i].exe, list[i].port,
               list[i].events, list[i].suspect,
               list[i].alive ? "运行中" : "已退出", up);
    }
}

/* Wait briefly for the freshly injected DLL to publish its port. */
static void report_target(DWORD pid)
{
    int i, tries;
    for (tries = 0; tries < 40; tries++) {
        INSTANCE list[MAX_INSTANCES];
        int n = discover(list, MAX_INSTANCES);
        for (i = 0; i < n; i++) {
            if (list[i].pid == pid && list[i].alive) {
                printf("  PID      : %lu\n", (unsigned long)pid);
                printf("  进程     : %s\n", list[i].exe);
                printf("  WebUI    : http://127.0.0.1:%d/\n", list[i].port);
                if (g_cfg.gui)
                    printf("  进程窗口 : 已在目标进程内创建（若该进程无桌面则只有 WebUI）\n");
                else
                    printf("  进程窗口 : 已禁用（--gui=0）\n");
                if (g_hubRunning)
                    printf("  控制台   : http://127.0.0.1:%d/\n", g_hubPort);
                return;
            }
        }
        Sleep(150);
    }
    printf("  [i] 注入已发起，但尚未收到监控端口的回报。\n");
    printf("      可用 --list 稍后查看；若目标进程立即退出，请检查 DLL 是否为 x64。\n");
}

static void banner(void)
{
    printf("\n");
    printf("  ProcWatch v" PW_VERSION "  -  进程行为监控\n");
    printf("  ==========================================\n\n");
}

static void usage(void)
{
    banner();
    printf("  用法:\n");
    printf("    injector.exe --exe <程序路径> [参数...]     启动并注入\n");
    printf("    injector.exe --pid <PID>                    注入到运行中的进程\n");
    printf("    injector.exe --list                         列出已监控进程\n");
    printf("    injector.exe --hub [--hub-port N]           启动聚合控制台\n\n");
    printf("  选项:\n");
    printf("    --dll <路径>      要注入的 DLL（默认与本程序同目录的 ProcWatch.dll）\n");
    printf("    --gui=0|1         进程内监控窗口           默认 1\n");
    printf("    --http=0|1        内嵌 WebUI 服务器        默认 1\n");
    printf("    --port=N          指定 WebUI 端口          默认自动\n");
    printf("    --log=0|1         同时写事件日志文件       默认 0\n");
    printf("    --previews=0|1    记录读写/收发的数据预览  默认 0\n");
    printf("    --risk=0|1        启用可疑行为规则         默认 1\n");
    printf("    --verbose=0|1     记录高频 API（如 GetProcAddress 全部调用）\n");
    printf("    --ring=N          事件环形缓冲条数         默认 8192\n");
    printf("    --no-elevate      目标要求管理员权限时不自动提权\n");
    printf("    --wait            注入后保持前台运行（配合 --hub 使用）\n\n");
    printf("  示例:\n");
    printf("    injector.exe --hub\n");
    printf("    injector.exe --exe C:\\Windows\\System32\\notepad.exe --hub\n");
    printf("    injector.exe --pid 4321 --previews=1\n\n");
    printf("  说明:\n");
    printf("    目标程序若声明需要管理员权限（清单里的 requireAdministrator），\n");
    printf("    本程序会自动通过 UAC 以管理员身份重启；注入到这类进程同理。\n\n");
}

/* --------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    int i;
    const char *exeToRun = NULL;
    DWORD pid = 0;
    int wantHub = 0, wantList = 0, waitAfter = 0, hubPort = PW_HUB_PORT;
    int allowElevate = 1;
    HANDLE readyEvent = NULL;
    char *childArgs[64];
    int childArgc = 0;
    char opts[1024];

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleA("ProcWatch Injector");
    /* Unbuffered: with --hub this process stays alive, so a redirected stdout
     * would otherwise never flush. */
    setvbuf(stdout, NULL, _IONBF, 0);
    pw_config_defaults(&g_cfg);

    /* Default to the DLL sitting next to injector.exe, not the current working
     * directory, which is rarely where the build output lives. */
    {
        char self[MAX_PATH * 2];
        DWORD n = GetModuleFileNameA(NULL, self, sizeof(self));
        int i;
        if (n > 0 && n < sizeof(self)) {
            for (i = (int)n - 1; i >= 0; i--) {
                if (self[i] == '\\' || self[i] == '/') {
                    self[i + 1] = 0;
                    break;
                }
            }
            pw_path_join(g_dllPath, sizeof(g_dllPath), self, "ProcWatch.dll");
        } else {
            pw_str_copy(g_dllPath, sizeof(g_dllPath), "ProcWatch.dll");
        }
    }

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--exe") && i + 1 < argc) {
            exeToRun = argv[++i];
        } else if (!strcmp(a, "--")) {
            /* Everything after "--" belongs to the target program. */
            while (i + 1 < argc && childArgc < 63) childArgs[childArgc++] = argv[++i];
        } else if (!strncmp(a, "--pid=", 6)) {
            pid = (DWORD)strtoul(a + 6, NULL, 10);
        } else if (!strcmp(a, "--pid") && i + 1 < argc) {
            pid = (DWORD)strtoul(argv[++i], NULL, 10);
        } else if (!strncmp(a, "--dll=", 6)) {
            pw_str_copy(g_dllPath, sizeof(g_dllPath), a + 6);
        } else if (!strcmp(a, "--dll") && i + 1 < argc) {
            pw_str_copy(g_dllPath, sizeof(g_dllPath), argv[++i]);
        } else if (!strcmp(a, "--list")) {
            wantList = 1;
        } else if (!strcmp(a, "--hub")) {
            wantHub = 1;
        } else if (!strncmp(a, "--hub-port=", 11)) {
            hubPort = atoi(a + 11);
        } else if (!strcmp(a, "--wait")) {
            waitAfter = 1;
        } else if (!strcmp(a, "--no-elevate")) {
            /* Internal: set when we re-launch ourselves elevated, so that
             * instance cannot bounce back and forth. */
            allowElevate = 0;
        } else if (!strcmp(a, "--verbose")) {
            g_verbose = 1;
        } else if (!strncmp(a, "--gui=", 6)) {
            g_cfg.gui = atoi(a + 6) ? 1 : 0;
        } else if (!strncmp(a, "--http=", 7)) {
            g_cfg.http = atoi(a + 7) ? 1 : 0;
        } else if (!strncmp(a, "--port=", 7)) {
            g_cfg.port = atoi(a + 7);
        } else if (!strncmp(a, "--log=", 6)) {
            g_cfg.log_file = atoi(a + 6) ? 1 : 0;
        } else if (!strncmp(a, "--previews=", 11)) {
            g_cfg.previews = atoi(a + 11) ? 1 : 0;
        } else if (!strncmp(a, "--risk=", 7)) {
            g_cfg.risk = atoi(a + 7) ? 1 : 0;
        } else if (!strncmp(a, "--verbose=", 10)) {
            g_cfg.verbose = atoi(a + 10) ? 1 : 0;
        } else if (!strncmp(a, "--ring=", 7)) {
            g_cfg.ring = (unsigned)atoi(a + 7);
            if (g_cfg.ring < 256) g_cfg.ring = 256;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help") || !strcmp(a, "/?")) {
            usage();
            return 0;
        } else if (childArgc < 63) {
            /* Anything we do not recognise is an argument of the target. */
            childArgs[childArgc++] = argv[i];
        }
    }
    childArgs[childArgc] = NULL;

    if (wantList) { banner(); print_instances(); return 0; }

    if (!exeToRun && !pid && !wantHub) { usage(); return 1; }

    /* Resolve the DLL to an absolute path: the target process has a different
     * working directory, and LoadLibraryW resolves relative paths against it. */
    {
        char full[MAX_PATH * 2];
        DWORD n = GetFullPathNameA(g_dllPath, sizeof(full), full, NULL);
        if (n > 0 && n < sizeof(full)) pw_str_copy(g_dllPath, sizeof(g_dllPath), full);
        if (GetFileAttributesA(g_dllPath) == INVALID_FILE_ATTRIBUTES) {
            if (exeToRun || pid) {
                fprintf(stderr, "[!] 找不到 DLL：%s\n", g_dllPath);
                fprintf(stderr, "    请先运行 build.bat 生成 ProcWatch.dll，或用 --dll 指定路径。\n");
                return 1;
            }
        }
    }

    pw_config_to_string(&g_cfg, opts, sizeof(opts));

    banner();

    if (exeToRun || pid) enable_debug_privilege();

    if (exeToRun) {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        char cmdline[4096];
        int k;

        /* The DLL reads its options from the environment, which the child
         * inherits because we pass a NULL environment block below. */
        SetEnvironmentVariableA(PW_OPTS_ENV, opts);

        _snprintf(cmdline, sizeof(cmdline), "\"%s\"", exeToRun);
        cmdline[sizeof(cmdline) - 1] = 0;
        for (k = 0; k < childArgc; k++) {
            pw_str_cat(cmdline, sizeof(cmdline), " ");
            pw_str_cat(cmdline, sizeof(cmdline), childArgs[k]);
        }

        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));

        printf("[*] 启动目标（挂起）：%s\n", cmdline);
        if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                            NULL, NULL, &si, &pi)) {
            DWORD e = GetLastError();
            if (e == ERROR_ELEVATION_REQUIRED) {
                fprintf(stderr, "[!] 目标要求管理员权限（错误码 740）。\n");
                if (allowElevate) try_relaunch_elevated();
                else fprintf(stderr, "    请右键以管理员身份运行本程序后重试。\n");
            } else {
                err("CreateProcess 失败：%s", cmdline);
                if (e == ERROR_FILE_NOT_FOUND)
                    fprintf(stderr, "    请检查程序路径是否存在。\n");
            }
            return 1;
        }

        /* Create the handshake before injecting, so we cannot miss the signal. */
        readyEvent = create_ready_event(pi.dwProcessId);

        printf("[*] 注入：%s\n", g_dllPath);
        if (inject_into(pi.dwProcessId, g_dllPath)) {
            printf("[+] 注入成功。\n");
            /* The target stays suspended until the import tables are repointed:
             * a compiler that hoisted an IAT load into a register before the
             * patch would otherwise keep calling the original function. */
            if (wait_ready(readyEvent, 15000)) {
                printf("[+] 挂钩安装完成，恢复目标线程运行。\n");
            } else {
                readyEvent = NULL;
                printf("[!] 等待挂钩安装超时，仍恢复目标运行（早期调用可能漏记）。\n");
            }
        } else {
            printf("[!] 注入失败，目标将以未监控状态继续运行。\n");
            if (readyEvent) { CloseHandle(readyEvent); readyEvent = NULL; }
        }
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);

        report_target(pi.dwProcessId);
        CloseHandle(pi.hProcess);
    } else if (pid) {
        printf("[*] 注入进程 PID %lu\n", (unsigned long)pid);
        /* No environment to inherit, so hand the options over on disk. */
        pw_config_write_pending(&g_cfg);
        readyEvent = create_ready_event(pid);
        if (inject_into(pid, g_dllPath)) {
            printf("[+] 注入成功。\n");
            printf(wait_ready(readyEvent, 15000)
                     ? "[+] 挂钩安装完成。\n"
                     : "[!] 等待挂钩安装超时。\n");
            readyEvent = NULL;
            report_target(pid);
        } else {
            if (readyEvent) { CloseHandle(readyEvent); readyEvent = NULL; }
            printf("[!] 注入失败。\n");
            return 1;
        }
    }

    if (wantHub) {
        if (hub_start(hubPort)) {
            printf("\n[*] 聚合控制台已启动：http://127.0.0.1:%d/\n", g_hubPort);
            printf("    按 Ctrl+C 退出（退出不影响已注入的进程）。\n\n");
            waitAfter = 1;
        } else {
            fprintf(stderr, "[!] 无法绑定控制台端口 %d（可能已在运行）。\n", hubPort);
        }
    }

    if (waitAfter && !wantHub) {
        printf("\n[*] 按回车键退出（退出不会卸载已注入的 DLL）。\n");
        getchar();
    } else if (!wantHub) {
        printf("\n[i] 提示：加 --hub 可同时启动聚合控制台，集中查看所有被监控进程。\n");
    }

    if (waitAfter) {
        /* Stay alive while the hub serves. */
        for (;;) Sleep(1000);
    }
    return 0;
}
