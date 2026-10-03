/* testtarget.c - a deliberately noisy program for exercising ProcWatch.
 *
 * It performs one example of every behaviour the monitor claims to report:
 * file creation/read/write/copy/move/delete, directory enumeration, registry
 * read and write, DNS lookups, a raw TCP connect, a WinHTTP request, a WinINet
 * request, process creation from both a normal directory and a temporary drop
 * directory, module loading, dynamic GetProcAddress, and read-write-execute
 * memory allocation.
 *
 * Nothing here is malicious and nothing leaves the machine: the "credential"
 * step only attempts to OPEN well-known paths (they fail, and the failure is the
 * interesting part), the drop-and-execute step copies this very executable into
 * %TEMP% and runs it with --child, and the registry key that is created is
 * deleted again before the program moves on.
 *
 *   testtarget.exe               run everything with 1.2s gaps, then hold
 *   testtarget.exe --fast        no gaps
 *   testtarget.exe --once        exit when finished
 *   testtarget.exe --hold 60     hold for 60 seconds afterwards
 *   testtarget.exe --child       child mode (prints and exits) */
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pw_lang.h"

/* MinGW's wininet.h and winhttp.h redefine INTERNET_SCHEME and URL_COMPONENTS
 * with incompatible types, so the four WinINet entry points used below are
 * declared by hand rather than pulling in wininet.h. MinGW auto-imports them
 * from wininet.dll at link time. */
#define INTERNET_OPEN_TYPE_PRECONFIG  0
#define INTERNET_FLAG_RELOAD          0x80000000u
#define INTERNET_FLAG_NO_CACHE_WRITE  0x04000000u
void *__stdcall InternetOpenA(const char *agent, unsigned long accessType,
                              const char *proxy, const char *proxyBypass,
                              unsigned long flags);
void *__stdcall InternetOpenUrlA(void *session, const char *url, const char *headers,
                                 unsigned long headersLen, unsigned long flags,
                                 unsigned long long context);
int   __stdcall InternetReadFile(void *handle, void *buffer, unsigned long toRead,
                                 unsigned long *read);
int   __stdcall InternetCloseHandle(void *handle);

static int g_gapMs = 1200;
static int g_once = 0;
static int g_holdSec = 300;
static char g_self[MAX_PATH];

static void hr(const char *title)
{
    printf("\n--- %s\n", title);
    fflush(stdout);
}

static void ok(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("    ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static void gap(void)
{
    if (g_gapMs > 0) Sleep(g_gapMs);
}

/* ------------------------------------------------------------------- files */

static void do_files(void)
{
    char temp[MAX_PATH], dir[MAX_PATH], f1[MAX_PATH], f2[MAX_PATH], f3[MAX_PATH];
    HANDLE h;
    DWORD written = 0;
    char data[256];
    char readback[256] = {0};
    DWORD got = 0;

    hr(L("文件操作：创建 / 写入 / 读取 / 复制 / 改名 / 枚举 / 删除"));

    GetTempPathA(sizeof(temp), temp);
    _snprintf(dir, sizeof(dir), "%sProcWatchTest", temp);
    dir[sizeof(dir) - 1] = 0;
    CreateDirectoryA(dir, NULL);
    _snprintf(f1, sizeof(f1), "%s\\sample.txt", dir);
    _snprintf(f2, sizeof(f2), "%s\\sample-copy.txt", dir);
    _snprintf(f3, sizeof(f3), "%s\\sample-renamed.txt", dir);
    f1[sizeof(f1) - 1] = f2[sizeof(f2) - 1] = f3[sizeof(f3) - 1] = 0;

    h = CreateFileA(f1, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        _snprintf(data, sizeof(data),
                  L("ProcWatch 测试数据 hello world 时间戳=%lu\r\n"), GetTickCount());
        data[sizeof(data) - 1] = 0;
        WriteFile(h, data, (DWORD)strlen(data), &written, NULL);
        CloseHandle(h);
        ok(L("写入 %s（%lu 字节）"), f1, (unsigned long)written);
    }
    gap();

    h = CreateFileA(f1, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        ReadFile(h, readback, sizeof(readback) - 1, &got, NULL);
        readback[got] = 0;
        CloseHandle(h);
        ok(L("读取回 %lu 字节"), (unsigned long)got);
    }
    gap();

    CopyFileA(f1, f2, FALSE);
    ok(L("复制 -> %s"), f2);
    gap();

    MoveFileExA(f2, f3, MOVEFILE_REPLACE_EXISTING);
    ok(L("改名 -> %s"), f3);
    gap();

    {
        char pattern[MAX_PATH];
        WIN32_FIND_DATAA fd;
        int n = 0;
        _snprintf(pattern, sizeof(pattern), "%s\\*", dir);
        pattern[sizeof(pattern) - 1] = 0;
        h = FindFirstFileA(pattern, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do { n++; } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
        ok(L("枚举目录，共 %d 个条目"), n);
    }
    gap();

    /* Deliberate probe of well-known credential stores. These opens fail on
     * purpose: writing tools flag the *attempt*, so the attempt is what we
     * reproduce here. Nothing is read and nothing is transmitted. */
    {
        const char *probes[] = {
            "\\Google\\Chrome\\User Data\\Default\\Login Data",
            "\\Microsoft\\Edge\\User Data\\Default\\Login Data",
            "\\Mozilla\\Firefox\\Profiles\\test\\key4.db",
            "\\.ssh\\id_rsa",
            "\\AppData\\Local\\Microsoft\\Credentials"
        };
        char base[MAX_PATH];
        DWORD n = GetEnvironmentVariableA("USERPROFILE", base, sizeof(base));
        int i;
        if (n > 0 && n < sizeof(base)) {
            for (i = 0; i < (int)(sizeof(probes) / sizeof(probes[0])); i++) {
                char p[MAX_PATH * 2];
                _snprintf(p, sizeof(p), "%s%s", base, probes[i]);
                p[sizeof(p) - 1] = 0;
                h = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
                if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
            }
            ok(L("尝试打开 %d 个凭据类路径（预期失败，用于验证规则匹配）"),
               (int)(sizeof(probes) / sizeof(probes[0])));
        }
    }
    gap();

    DeleteFileA(f1);
    DeleteFileA(f3);
    RemoveDirectoryA(dir);
    ok(L("清理完成"));
}

/* ---------------------------------------------------------------- registry */

static void do_registry(void)
{
    HKEY key;
    DWORD disp = 0, value = 0x1234ABCD, size = sizeof(value), type = 0;
    LSTATUS st;

    hr(L("注册表：创建键 / 写入值 / 读回 / 删除"));

    st = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\ProcWatchTest", 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key, &disp);
    if (st == ERROR_SUCCESS) {
        ok(L("创建 HKCU\\Software\\ProcWatchTest（%s）"),
           disp == REG_CREATED_NEW_KEY ? L("新建") : L("已存在"));

        RegSetValueExA(key, "Marker", 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
        ok(L("写入 REG_DWORD Marker = 0x%08lX"), (unsigned long)value);
        gap();

        RegSetValueExA(key, "Note", 0, REG_SZ, (const BYTE *)"procwatch test",
                       (DWORD)(strlen("procwatch test") + 1));
        ok(L("写入 REG_SZ Note"));
        gap();

        st = RegQueryValueExA(key, "Marker", NULL, &type, (LPBYTE)&value, &size);
        ok(L("读回 Marker = 0x%08lX（%s）"), (unsigned long)value,
           st == ERROR_SUCCESS ? L("成功") : L("失败"));
        RegCloseKey(key);
        gap();

        RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\ProcWatchTest");
        ok(L("删除测试键"));
    } else {
        ok(L("创建注册表键失败（%ld）"), (long)st);
    }
    gap();

    /* Reading the current proxy configuration is normal, and exactly the kind of
     * context the monitor reports alongside the HTTP traffic. */
    {
        HKEY k;
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                          "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                          0, KEY_READ, &k) == ERROR_SUCCESS) {
            char proxy[512];
            DWORD cb = sizeof(proxy), t = 0;
            proxy[0] = 0;
            if (RegQueryValueExA(k, "ProxyServer", NULL, &t, (LPBYTE)proxy, &cb) == ERROR_SUCCESS)
                ok(L("系统代理设置为：%s"), proxy);
            else
                ok(L("当前未配置系统代理"));
            RegCloseKey(k);
        }
    }

    /* And the autostart key is read (never written) so the read shows up with
     * the same path shape that malware would write to. */
    {
        HKEY k;
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                          "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          0, KEY_READ, &k) == ERROR_SUCCESS) {
            DWORD n = 0, cbName = 256;
            char name[256];
            while (cbName < 256 && RegEnumValueA(k, n, name, &cbName, NULL, NULL, NULL, NULL)
                                  == ERROR_SUCCESS) {
                n++;
                cbName = 256;
            }
            ok(L("现有 %lu 个自启动项（仅读取，未修改）"), (unsigned long)n);
            RegCloseKey(k);
        }
    }

    /* Persistence detection, demonstrated without touching a real autostart
     * location: a key whose path has the same shape as the Run key, created
     * under our own test key and deleted immediately. The rule matches the path,
     * which is exactly what this proves - nothing outside HKCU\Software\
     * ProcWatchTest is written. To see the same rule fire for real, drop a
     * shortcut into shell:startup yourself. */
    {
        HKEY k;
        const char *sim = "Software\\ProcWatchTest\\CurrentVersion\\Run";
        if (RegCreateKeyExA(HKEY_CURRENT_USER, sim, 0, NULL, REG_OPTION_NON_VOLATILE,
                            KEY_ALL_ACCESS, NULL, &k, NULL) == ERROR_SUCCESS) {
            const char *payload = "C:\\demo\\payload.exe";
            RegSetValueExA(k, "ProcWatchDemo", 0, REG_SZ, (const BYTE *)payload,
                           (DWORD)(strlen(payload) + 1));
            ok(L("写入模拟自启动路径 %s（仅测试键，未触碰真实 Run 键）"), sim);
            RegCloseKey(k);
            gap();
            RegDeleteKeyA(HKEY_CURRENT_USER, sim);
            RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\ProcWatchTest\\CurrentVersion");
        }
    }
}

/* ----------------------------------------------------------------- network */

static void do_network(void)
{
    WSADATA wsa;
    SOCKET s;
    struct addrinfo hints, *res = NULL;
    char addrText[64] = {0};

    hr(L("网络：DNS 解析 / TCP 连接 / 发送与接收"));

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { ok(L("Winsock 初始化失败")); return; }

    {
        SOCKET dgram = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (dgram != INVALID_SOCKET) {
            ok(L("创建 UDP 套接字（演示 socket 钩子）"));
            closesocket(dgram);
        }
    }
    gap();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo("example.com", "80", &hints, &res) == 0 && res) {
        {
            struct sockaddr_in *v4 = (struct sockaddr_in *)res->ai_addr;
            unsigned int ip = (unsigned int)ntohl(v4->sin_addr.s_addr);
            _snprintf(addrText, sizeof(addrText), "%u.%u.%u.%u",
                      (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
        }
        ok(L("DNS 解析 example.com -> %s"), addrText);
        gap();

        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET) {
            if (connect(s, res->ai_addr, (int)res->ai_addrlen) == 0) {
                const char *req = "HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n";
                char buf[512];
                int n;
                ok(L("TCP 连接成功，发送裸 HTTP 请求"));
                send(s, req, (int)strlen(req), 0);
                n = recv(s, buf, sizeof(buf) - 1, 0);
                if (n > 0) { buf[n] = 0; ok(L("收到 %d 字节响应"), n); }
                else ok(L("未收到响应（可能无外网或已被防火墙丢弃）"));
            } else {
                ok(L("TCP 连接失败（离线或代理环境下属正常，钩子仍然记录）"));
            }
            closesocket(s);
        }
        freeaddrinfo(res);
    } else {
        ok(L("DNS 解析失败（离线环境属正常）"));
    }

    WSACleanup();
}

/* -------------------------------------------------------------------- HTTP */

static void do_http_winhttp(void)
{
    HINTERNET session, conn, req;
    DWORD status = 0, len = sizeof(status);

    hr(L("HTTP（WinHTTP）：会话 / 连接 / 请求 / 响应头"));

    session = WinHttpOpen(L"ProcWatchTest/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        ok(L("WinHttpOpen 失败（%lu）"), (unsigned long)GetLastError());
        return;
    }
    ok(L("WinHttpOpen 成功"));
    gap();

    conn = WinHttpConnect(session, L"example.com", 80, 0);
    if (conn) {
        ok(L("WinHttpConnect 成功"));
        req = WinHttpOpenRequest(conn, L"GET", L"/", NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (req) {
            if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                ok(L("请求已发送"));
                if (WinHttpReceiveResponse(req, NULL)) {
                    if (WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE |
                                                 WINHTTP_QUERY_FLAG_NUMBER,
                                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                                            WINHTTP_NO_HEADER_INDEX))
                        ok(L("HTTP 状态码 %lu"), (unsigned long)status);
                }
            } else {
                ok(L("发送失败（离线属正常）"));
            }
            WinHttpCloseHandle(req);
        }
        WinHttpCloseHandle(conn);
    } else {
        ok(L("WinHttpConnect 失败（离线属正常）"));
    }
    WinHttpCloseHandle(session);
}

static void do_http_wininet(void)
{
    HINTERNET net, url;

    hr(L("HTTP（WinINet）：InternetOpen / InternetOpenUrl / InternetReadFile"));

    net = InternetOpenA("ProcWatchTest/1.0 (WinINet)",
                        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!net) { ok(L("InternetOpen 失败（%lu）"), (unsigned long)GetLastError()); return; }
    ok(L("InternetOpen 成功（使用系统代理配置）"));
    gap();

    url = InternetOpenUrlA(net, "http://example.com/", NULL, 0,
                           INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (url) {
        char buf[1024];
        DWORD got = 0;
        ok(L("InternetOpenUrl 成功"));
        if (InternetReadFile(url, buf, sizeof(buf) - 1, &got) && got) {
            buf[got] = 0;
            ok(L("读取到 %lu 字节响应体"), (unsigned long)got);
        } else {
            ok(L("未读到内容（离线属正常）"));
        }
        InternetCloseHandle(url);
    } else {
        ok(L("InternetOpenUrl 失败（离线属正常）"));
    }
    InternetCloseHandle(net);
}

/* ------------------------------------------------------- processes / modules */

static void do_process(void)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char temp[MAX_PATH], drop[MAX_PATH];
    char cmd[1024];

    hr(L("进程：系统工具调用 / 临时目录落地并执行"));

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    _snprintf(cmd, sizeof(cmd), L("cmd.exe /c echo ProcWatch 测试输出 & timeout /t 1 >nul"));
    cmd[sizeof(cmd) - 1] = 0;
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        ok(L("启动 cmd.exe（PID %lu）"), (unsigned long)pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        ok(L("启动 cmd.exe 失败"));
    }
    gap();

    /* Drop a copy of ourselves in %TEMP% and run it: the classic
     * "write to a writable directory, then execute from there" pattern. */
    GetTempPathA(sizeof(temp), temp);
    _snprintf(drop, sizeof(drop), "%sProcWatchTest-dropped.exe", temp);
    drop[sizeof(drop) - 1] = 0;

    if (CopyFileA(g_self, drop, FALSE)) {
        ok(L("已把自身复制到 %s"), drop);
        gap();

        _snprintf(cmd, sizeof(cmd), "\"%s\" --child", drop);
        cmd[sizeof(cmd) - 1] = 0;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            ok(L("启动临时目录中的副本（PID %lu）"), (unsigned long)pi.dwProcessId);
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        gap();
        DeleteFileA(drop);
        ok(L("已删除副本"));
    } else {
        ok(L("复制自身失败（%lu）"), (unsigned long)GetLastError());
    }
}

static void do_modules(void)
{
    HMODULE m;
    FARPROC p;
    typedef LPVOID (WINAPI *PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    PFN_VirtualAlloc dyn;

    hr(L("模块：加载 DLL / 动态解析函数地址"));

    m = LoadLibraryA("version.dll");
    if (m) { ok(L("LoadLibraryA(\"version.dll\") 成功")); FreeLibrary(m); }
    else    ok(L("LoadLibraryA(\"version.dll\") 失败"));

    m = LoadLibraryA("winhttp.dll");
    if (m) { ok(L("LoadLibraryA(\"winhttp.dll\") 成功")); FreeLibrary(m); }

    /* Resolving an API at runtime instead of importing it is the shape of an
     * unpacker or a loader stub, so the monitor records the name. */
    p = GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    ok("GetProcAddress(kernel32, VirtualAlloc) = %p", (void *)p);

    dyn = (PFN_VirtualAlloc)(void *)p;
    if (dyn) {
        LPVOID mem = dyn(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mem) {
            memset(mem, 0x90, 16);
            ok(L("通过动态地址申请 4096 字节并写入"));
            VirtualFree(mem, 0, MEM_RELEASE);
        }
    }
}

static void do_memory(void)
{
    LPVOID mem;
    DWORD old = 0;
    HANDLE self = GetCurrentProcess();
    SIZE_T wrote = 0;
    unsigned char payload[64];

    hr(L("内存：可写可执行内存 / 跨进程写内存与改权限"));

    /* PAGE_EXECUTE_READWRITE is what a shellcode loader asks for. We allocate,
     * write a NOP sled into it and release it - nothing is executed. */
    mem = VirtualAlloc(NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem) {
        memset(mem, 0x90, 64);
        ok(L("申请 PAGE_EXECUTE_READWRITE 内存 %p（未执行任何内容）"), mem);
        gap();
        VirtualProtect(mem, 8192, PAGE_READONLY, &old);
        ok(L("改权限为 PAGE_READONLY（原权限 0x%lX）"), (unsigned long)old);
        VirtualFree(mem, 0, MEM_RELEASE);
    }

    /* Same primitives against our own process: this is the exact call sequence
     * an injector uses, minus the "someone else's process" part. */
    mem = VirtualAllocEx(self, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        memset(payload, 0xCC, sizeof(payload));
        if (WriteProcessMemory(self, mem, payload, sizeof(payload), &wrote))
            ok(L("向自身进程写入 %llu 字节（模拟注入的第一阶段）"),
               (unsigned long long)wrote);
        VirtualProtectEx(self, mem, 4096, PAGE_EXECUTE_READ, &old);
        ok(L("把该内存改为可执行"));
        VirtualFreeEx(self, mem, 0, MEM_RELEASE);
    }
}

/* --------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    int i;
    int lang = PW_LANG_AUTO;

    SetConsoleOutputCP(CP_UTF8);

    /* The language has to be resolved before the first string is printed, and
     * the title below is already one of them. Options are scanned up front for
     * that reason; the loop further down still handles the behaviour flags. */
    for (i = 1; i < argc; i++)
        if (!strncmp(argv[i], "--lang=", 7)) lang = pw_lang_parse(argv[i] + 7);
    pw_lang_init(lang);

    SetConsoleTitleA(L("ProcWatch 测试靶机"));

    GetModuleFileNameA(NULL, g_self, sizeof(g_self));

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--child")) {
            printf(L("[child] 我是被释放到临时目录的副本，PID %lu，马上退出。\n"),
                   (unsigned long)GetCurrentProcessId());
            Sleep(500);
            return 0;
        }
        if (!strcmp(argv[i], "--fast")) g_gapMs = 0;
        if (!strcmp(argv[i], "--once")) g_once = 1;
        if (!strcmp(argv[i], "--hold") && i + 1 < argc) g_holdSec = atoi(argv[++i]);
    }

    printf("==========================================================\n");
    printf(L("  ProcWatch 测试靶机  (PID %lu)\n"), (unsigned long)GetCurrentProcessId());
    printf(L("  每一步都会产生可被监控端捕获的行为，顺序执行。\n"));
    printf(L("  所有产物（文件/注册表键/子进程）都会在结束时清理。\n"));
    printf("==========================================================\n");
    fflush(stdout);

    do_files();      gap();
    do_registry();   gap();
    do_network();    gap();
    do_http_winhttp(); gap();
    do_http_wininet(); gap();
    do_process();    gap();
    do_modules();    gap();
    do_memory();

    printf("\n==========================================================\n");
    printf(L("  全部行为执行完毕。\n"));
    if (g_once) {
        printf(L("  --once 指定，退出。\n"));
        return 0;
    }
    printf(L("  保持运行 %d 秒，方便在监控窗口/WebUI 里查看结果。\n"), g_holdSec);
    printf(L("  按 Ctrl+C 或关闭本窗口即可退出。\n"));
    printf("==========================================================\n");
    fflush(stdout);

    /* Keep a little activity going so the monitor keeps showing a live process
     * rather than a frozen snapshot, and so the window stays observable. */
    {
        int elapsed = 0;
        char temp[MAX_PATH], beat[MAX_PATH];
        GetTempPathA(sizeof(temp), temp);
        _snprintf(beat, sizeof(beat), "%sProcWatchTest-heartbeat.tmp", temp);
        beat[sizeof(beat) - 1] = 0;

        while (elapsed < g_holdSec) {
            HANDLE h = CreateFileA(beat, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                DWORD w = 0;
                char line[128];
                _snprintf(line, sizeof(line), "heartbeat %d\r\n", elapsed);
                line[sizeof(line) - 1] = 0;
                WriteFile(h, line, (DWORD)strlen(line), &w, NULL);
                CloseHandle(h);
            }
            Sleep(3000);
            elapsed += 3;
            if (elapsed % 15 == 0) {
                printf(L("  [心跳] 已运行 %d 秒，仍被监控中…\n"), elapsed);
                fflush(stdout);
            }
        }
        DeleteFileA(beat);
    }
    return 0;
}
