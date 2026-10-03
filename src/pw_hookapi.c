/* pw_hookapi.c - the hooks themselves.
 *
 * Every hook follows the same shape:
 *   1. save LastError
 *   2. bail out immediately when we are not observing (own threads, paused,
 *      detached) - the original runs untouched
 *   3. call the original
 *   4. report what happened, with the return value and byte counts
 *   5. restore LastError and return
 *
 * Nothing here allocates, and nothing here calls an API we hook, so a hook can
 * never re-enter itself. Expensive detail (handle -> path resolution, payload
 * previews) only happens for events we are actually going to keep. */
#include "pw_hooks.h"
#include "pw_state.h"
#include "pw_hookutil.h"
#include "pw_hookapi_http.h"
#include "pw_util.h"
#include <ws2tcpip.h>
#include <wininet.h>
#include <shellapi.h>
#include <string.h>

/* Short names for the shared helpers so the hook bodies stay readable. */
#define observing()          pw_observing()
#define fmt                  pw_fmt
#define preview              pw_preview
#define summarise_headers    pw_summarise_headers

/* ------------------------------------------------- handle -> path cache
 * ReadFile/WriteFile only receive a handle. The CreateFile hook stores the name
 * the caller used; handles that predate the injection are resolved once through
 * GetFinalPathNameByHandleW (which we do not hook). */

#define HCACHE_SLOTS 1024

typedef struct {
    HANDLE       h;
    unsigned int stamp;
    char         path[240];       /* truncated path is fine for a log line */
} HCENT;

static HCENT            g_hcache[HCACHE_SLOTS];
static unsigned int     g_hcache_stamp = 0;
static CRITICAL_SECTION g_hcache_cs;
static int              g_hcache_ready = 0;

static void hcache_init(void)
{
    if (g_hcache_ready) return;
    InitializeCriticalSection(&g_hcache_cs);
    g_hcache_ready = 1;
}

/* Called once from the injection thread before any hook is installed. */
void pw_hookapi_init(void);
void pw_hookapi_init(void)
{
    hcache_init();
}

static unsigned int hcache_hash(HANDLE h)
{
    return (unsigned int)(((ULONG_PTR)h >> 2) % HCACHE_SLOTS);
}

static void hcache_put(HANDLE h, const char *utf8path)
{
    unsigned int i, slot;
    if (!g_hcache_ready || !h || h == INVALID_HANDLE_VALUE) return;
    EnterCriticalSection(&g_hcache_cs);
    slot = hcache_hash(h);
    for (i = 0; i < 8; i++) {
        HCENT *e = &g_hcache[(slot + i) % HCACHE_SLOTS];
        if (e->h == h || e->h == NULL) {
            e->h = h;
            e->stamp = ++g_hcache_stamp;
            pw_str_copy(e->path, sizeof(e->path), utf8path);
            LeaveCriticalSection(&g_hcache_cs);
            return;
        }
    }
    /* Bucket full: evict the oldest of the eight. */
    {
        HCENT *victim = &g_hcache[slot];
        for (i = 1; i < 8; i++) {
            HCENT *e = &g_hcache[(slot + i) % HCACHE_SLOTS];
            if (e->stamp < victim->stamp) victim = e;
        }
        victim->h = h;
        victim->stamp = ++g_hcache_stamp;
        pw_str_copy(victim->path, sizeof(victim->path), utf8path);
    }
    LeaveCriticalSection(&g_hcache_cs);
}

static void hcache_del(HANDLE h)
{
    unsigned int i, slot;
    if (!g_hcache_ready || !h) return;
    EnterCriticalSection(&g_hcache_cs);
    slot = hcache_hash(h);
    for (i = 0; i < 8; i++) {
        HCENT *e = &g_hcache[(slot + i) % HCACHE_SLOTS];
        if (e->h == h) { e->h = NULL; e->path[0] = 0; break; }
    }
    LeaveCriticalSection(&g_hcache_cs);
}

/* Returns 1 and fills `out` when the handle maps to a known path. */
static int hcache_get(HANDLE h, char *out, int outsz)
{
    unsigned int i, slot;
    int found = 0;
    if (!h || h == INVALID_HANDLE_VALUE || outsz <= 0) return 0;
    out[0] = 0;
    if (!g_hcache_ready) return 0;

    EnterCriticalSection(&g_hcache_cs);
    slot = hcache_hash(h);
    for (i = 0; i < 8; i++) {
        HCENT *e = &g_hcache[(slot + i) % HCACHE_SLOTS];
        if (e->h == h) {
            pw_str_copy(out, outsz, e->path);
            found = 1;
            break;
        }
    }
    LeaveCriticalSection(&g_hcache_cs);
    if (found) return 1;

    /* Unknown handle: ask the kernel once, then remember the answer. */
    {
        wchar_t wpath[MAX_PATH * 2];
        DWORD n = GetFinalPathNameByHandleW(h, wpath, (DWORD)(MAX_PATH * 2),
                                            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (n > 0 && n < MAX_PATH * 2) {
            char utf8[MAX_PATH * 2];
            pw_wide_to_utf8(wpath, utf8, sizeof(utf8));
            pw_str_copy(out, outsz, utf8);
            hcache_put(h, utf8);
            return 1;
        }
        if (GetFileType(h) == FILE_TYPE_PIPE) {
            pw_str_copy(out, outsz, "(管道/命名管道)");
            hcache_put(h, out);
            return 1;
        }
        if (GetFileType(h) == FILE_TYPE_CHAR) {
            pw_str_copy(out, outsz, "(字符设备/控制台)");
            hcache_put(h, out);
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------- description strings */

static void access_str(DWORD a, char *out, int n)
{
    out[0] = 0;
    if (a == 0 || a == GENERIC_READ) { pw_str_copy(out, n, a ? "READ" : "查询属性"); return; }
    if (a & GENERIC_READ)    pw_str_cat(out, n, "READ ");
    if (a & GENERIC_WRITE)   pw_str_cat(out, n, "WRITE ");
    if (a & FILE_APPEND_DATA) pw_str_cat(out, n, "APPEND ");
    if (a & DELETE)          pw_str_cat(out, n, "DELETE ");
    if (a & FILE_EXECUTE)    pw_str_cat(out, n, "EXECUTE ");
    if (a & WRITE_DAC)       pw_str_cat(out, n, "WRITE_DAC ");
    if (a & WRITE_OWNER)     pw_str_cat(out, n, "WRITE_OWNER ");
    if (!out[0]) fmt(out, n, "0x%08X", (unsigned)a);
}

static const char *disp_str(DWORD d)
{
    switch (d) {
    case CREATE_NEW:        return "CREATE_NEW";
    case CREATE_ALWAYS:     return "CREATE_ALWAYS";
    case OPEN_EXISTING:     return "OPEN_EXISTING";
    case OPEN_ALWAYS:       return "OPEN_ALWAYS";
    case TRUNCATE_EXISTING: return "TRUNCATE_EXISTING";
    default:                return "?";
    }
}

static const char *root_key_name(HKEY k)
{
    if (k == HKEY_LOCAL_MACHINE)  return "HKLM";
    if (k == HKEY_CURRENT_USER)   return "HKCU";
    if (k == HKEY_CLASSES_ROOT)   return "HKCR";
    if (k == HKEY_USERS)          return "HKU";
    if (k == HKEY_CURRENT_CONFIG) return "HKCC";
    if (k == HKEY_PERFORMANCE_DATA) return "HKPD";
    return "(子键)";
}

/* Resolve the full path behind a registry handle. NtQueryKey with
 * KeyNameInformation is the only way to do this in one call, and it is not one
 * of the functions we hook, so calling it here cannot recurse. Resolved once,
 * lazily, through our own import table (which is never patched). */
typedef LONG (NTAPI *PFN_NtQueryKey)(HANDLE, int, PVOID, ULONG, PULONG);
#define PW_KEY_NAME_INFORMATION 3

static PFN_NtQueryKey g_NtQueryKey = NULL;
static int            g_NtQueryKey_tried = 0;

static void reg_key_path(HKEY key, char *out, int n)
{
    unsigned char buf[1024];
    ULONG need = 0;
    /* KEY_NAME_INFORMATION { ULONG TitleIndex; ULONG Type; ULONG NameLength; WCHAR Name[]; } */
    unsigned long nameLen;
    const wchar_t *name;

    out[0] = 0;
    if (!key) { pw_str_copy(out, n, "(空键)"); return; }

    if (!g_NtQueryKey_tried) {
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        g_NtQueryKey_tried = 1;
        if (nt) g_NtQueryKey = (PFN_NtQueryKey)(void *)GetProcAddress(nt, "NtQueryKey");
    }
    if (!g_NtQueryKey) { pw_str_copy(out, n, "(注册表句柄)"); return; }

    if (g_NtQueryKey((HANDLE)key, PW_KEY_NAME_INFORMATION, buf, sizeof(buf), &need) != 0) {
        pw_str_copy(out, n, "(注册表句柄)");
        return;
    }
    nameLen = *(unsigned long *)(buf + 8);
    name = (const wchar_t *)(buf + 12);

    {
        char utf8[900];
        int i;
        pw_wide_to_utf8(name, utf8, sizeof(utf8));
        /* \REGISTRY\MACHINE\... -> HKLM\...   \REGISTRY\USER\<sid>\... -> HKCU\... */
        if (!_strnicmp(utf8, "\\REGISTRY\\MACHINE\\", 18)) {
            fmt(out, n, "HKLM\\%s", utf8 + 18);
        } else if (!_strnicmp(utf8, "\\REGISTRY\\USER\\", 15)) {
            const char *rest = utf8 + 15;
            const char *next = strchr(rest, '\\');
            fmt(out, n, "HKCU\\%s", next ? next + 1 : rest);
        } else {
            pw_str_copy(out, n, utf8);
        }
        for (i = 0; out[i]; i++) if (out[i] == '/') out[i] = '\\';
        (void)nameLen;
    }
}

#define REGSAM_STR(v) (((v) & KEY_WRITE) ? "写" : ((v) & KEY_READ) ? "读" : "查询")

/* Path for the pre-opened root-key form (RegOpenKeyExW / RegCreateKeyExW). */
static void reg_path_root(HKEY root, LPCWSTR sub, char *out, int n)
{
    char s[320];
    pw_wide_to_utf8(sub, s, sizeof(s));
    fmt(out, n, "%s\\%s", root_key_name(root), s);
}

static void reg_path_root_a(HKEY root, LPCSTR sub, char *out, int n)
{
    char s[320];
    pw_ansi_to_utf8(sub, s, sizeof(s));
    fmt(out, n, "%s\\%s", root_key_name(root), s);
}

/* --------------------------------------------------------------- file hooks */

static HANDLE (WINAPI *real_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                         DWORD, DWORD, HANDLE);
static HANDLE (WINAPI *real_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                         DWORD, DWORD, HANDLE);
static BOOL   (WINAPI *real_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL   (WINAPI *real_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL   (WINAPI *real_DeleteFileW)(LPCWSTR);
static BOOL   (WINAPI *real_DeleteFileA)(LPCSTR);
static BOOL   (WINAPI *real_MoveFileExW)(LPCWSTR, LPCWSTR, DWORD);
static BOOL   (WINAPI *real_CopyFileW)(LPCWSTR, LPCWSTR, BOOL);
static BOOL   (WINAPI *real_CreateDirectoryW)(LPCWSTR, LPSECURITY_ATTRIBUTES);
static BOOL   (WINAPI *real_RemoveDirectoryW)(LPCWSTR);
static HANDLE (WINAPI *real_FindFirstFileW)(LPCWSTR, LPWIN32_FIND_DATAW);
static HANDLE (WINAPI *real_FindFirstFileExW)(LPCWSTR, FINDEX_INFO_LEVELS,
                                              LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
static BOOL   (WINAPI *real_SetFileAttributesW)(LPCWSTR, DWORD);
static BOOL   (WINAPI *real_CloseHandle)(HANDLE);

static HANDLE WINAPI hook_CreateFileW(LPCWSTR name, DWORD access, DWORD share,
                                      LPSECURITY_ATTRIBUTES sa, DWORD disp,
                                      DWORD flags, HANDLE tmpl)
{
    DWORD err = GetLastError();
    HANDLE h;
    int obs = observing();

    h = real_CreateFileW(name, access, share, sa, disp, flags, tmpl);

    if (obs) {
        char path[PW_TGT_LEN], det[PW_DET_LEN], acc[96];
        if (!name) pw_str_copy(path, sizeof(path), "(空文件名)");
        else pw_wide_to_utf8(name, path, sizeof(path));
        access_str(access, acc, sizeof(acc));
        fmt(det, sizeof(det), "%s | 模式 %s | 共享 0x%X%s",
            acc, disp_str(disp), (unsigned)share,
            (flags & FILE_FLAG_DELETE_ON_CLOSE) ? " | 关闭即删除" : "");
        pw_report(PW_CAT_FILE,
                  (h == INVALID_HANDLE_VALUE) ? PW_LVL_WARN : PW_LVL_INFO,
                  "CreateFileW", path, det, 0, (int)GetLastError());
        if (h != INVALID_HANDLE_VALUE) hcache_put(h, path);
    }
    SetLastError(err);
    return h;
}

static HANDLE WINAPI hook_CreateFileA(LPCSTR name, DWORD access, DWORD share,
                                      LPSECURITY_ATTRIBUTES sa, DWORD disp,
                                      DWORD flags, HANDLE tmpl)
{
    DWORD err = GetLastError();
    HANDLE h;
    int obs = observing();

    h = real_CreateFileA(name, access, share, sa, disp, flags, tmpl);

    if (obs) {
        char det[PW_DET_LEN], acc[96];
        access_str(access, acc, sizeof(acc));
        fmt(det, sizeof(det), "%s | 模式 %s", acc, disp_str(disp));
        pw_report(PW_CAT_FILE,
                  (h == INVALID_HANDLE_VALUE) ? PW_LVL_WARN : PW_LVL_INFO,
                  "CreateFileA", name ? name : "(空)", det, 0, (int)GetLastError());
        if (h != INVALID_HANDLE_VALUE && name) hcache_put(h, name);
    }
    SetLastError(err);
    return h;
}

static BOOL WINAPI hook_ReadFile(HANDLE f, LPVOID buf, DWORD toRead,
                                 LPDWORD read, LPOVERLAPPED ov)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();

    ok = real_ReadFile(f, buf, toRead, read, ov);

    if (obs) {
        DWORD got = (read && ok) ? *read : 0;
        char path[PW_TGT_LEN], det[PW_DET_LEN];
        hcache_get(f, path, sizeof(path));
        if (ok && got) {
            char pv[PW_DET_LEN];
            preview(buf, got, pv, sizeof(pv));
            fmt(det, sizeof(det), "读取 %u 字节%s%s", (unsigned)got,
                pv[0] ? "  " : "", pv);
        } else {
            fmt(det, sizeof(det), "读取失败（请求 %u 字节，错误 %lu）",
                (unsigned)toRead, (unsigned long)GetLastError());
        }
        pw_report(PW_CAT_FILE, ok ? PW_LVL_INFO : PW_LVL_WARN,
                  "ReadFile", path[0] ? path : "(未知句柄)", det, got,
                  (int)GetLastError());
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_WriteFile(HANDLE f, LPCVOID buf, DWORD toWrite,
                                  LPDWORD written, LPOVERLAPPED ov)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();

    ok = real_WriteFile(f, buf, toWrite, written, ov);

    if (obs) {
        DWORD put = (written && ok) ? *written : 0;
        char path[PW_TGT_LEN], det[PW_DET_LEN];
        hcache_get(f, path, sizeof(path));
        if (ok && put) {
            char pv[PW_DET_LEN];
            preview(buf, put, pv, sizeof(pv));
            fmt(det, sizeof(det), "写入 %u 字节%s%s", (unsigned)put,
                pv[0] ? "  " : "", pv);
        } else {
            fmt(det, sizeof(det), "写入失败（请求 %u 字节，错误 %lu）",
                (unsigned)toWrite, (unsigned long)GetLastError());
        }
        pw_report(PW_CAT_FILE, ok ? PW_LVL_INFO : PW_LVL_WARN,
                  "WriteFile", path[0] ? path : "(未知句柄)", det, put,
                  (int)GetLastError());
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_DeleteFileW(LPCWSTR name)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_DeleteFileW(name);
    if (obs) {
        char path[PW_TGT_LEN];
        pw_wide_to_utf8(name, path, sizeof(path));
        pw_report(PW_CAT_FILE, ok ? PW_LVL_WARN : PW_LVL_WARN, "DeleteFileW",
                  path, ok ? "删除成功" : "删除失败", 0, (int)GetLastError());
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_DeleteFileA(LPCSTR name)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_DeleteFileA(name);
    if (obs)
        pw_report(PW_CAT_FILE, PW_LVL_WARN, "DeleteFileA", name ? name : "(空)",
                  ok ? "删除成功" : "删除失败", 0, (int)GetLastError());
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_MoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_MoveFileExW(from, to, flags);
    if (obs) {
        char a[200], b[200], det[PW_DET_LEN];
        pw_wide_to_utf8(from, a, sizeof(a));
        pw_wide_to_utf8(to, b, sizeof(b));
        fmt(det, sizeof(det), "重命名/移动到 %s%s", b,
            (flags & MOVEFILE_REPLACE_EXISTING) ? " | 覆盖已存在文件" : "");
        pw_report(PW_CAT_FILE, PW_LVL_WARN, "MoveFileExW", a, det, 0, (int)GetLastError());
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_CopyFileW(LPCWSTR from, LPCWSTR to, BOOL failIfExists)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_CopyFileW(from, to, failIfExists);
    if (obs) {
        char a[200], b[200], det[PW_DET_LEN];
        pw_wide_to_utf8(from, a, sizeof(a));
        pw_wide_to_utf8(to, b, sizeof(b));
        fmt(det, sizeof(det), "复制到 %s", b);
        pw_report(PW_CAT_FILE, PW_LVL_INFO, "CopyFileW", a, det, 0, (int)GetLastError());
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_CreateDirectoryW(LPCWSTR name, LPSECURITY_ATTRIBUTES sa)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_CreateDirectoryW(name, sa);
    if (obs) {
        char path[PW_TGT_LEN];
        pw_wide_to_utf8(name, path, sizeof(path));
        pw_report(PW_CAT_FILE, PW_LVL_INFO, "CreateDirectoryW", path,
                  ok ? "目录已创建" : "创建失败", 0, (int)GetLastError());
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_RemoveDirectoryW(LPCWSTR name)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_RemoveDirectoryW(name);
    if (obs) {
        char path[PW_TGT_LEN];
        pw_wide_to_utf8(name, path, sizeof(path));
        pw_report(PW_CAT_FILE, PW_LVL_WARN, "RemoveDirectoryW", path,
                  ok ? "目录已删除" : "删除失败", 0, (int)GetLastError());
    }
    SetLastError(err);
    return ok;
}

static HANDLE WINAPI hook_FindFirstFileW(LPCWSTR pattern, LPWIN32_FIND_DATAW data)
{
    DWORD err = GetLastError();
    HANDLE h;
    int obs = observing();
    h = real_FindFirstFileW(pattern, data);
    if (obs) {
        char path[PW_TGT_LEN], det[PW_DET_LEN];
        pw_wide_to_utf8(pattern, path, sizeof(path));
        fmt(det, sizeof(det), "枚举目录内容%s",
            (h == INVALID_HANDLE_VALUE) ? "（无匹配）" : "");
        pw_report(PW_CAT_FILE, PW_LVL_INFO, "FindFirstFileW", path, det, 0, (int)GetLastError());
    }
    SetLastError(err);
    return h;
}

static HANDLE WINAPI hook_FindFirstFileExW(LPCWSTR pattern, FINDEX_INFO_LEVELS lvl,
                                           LPVOID data, FINDEX_SEARCH_OPS op,
                                           LPVOID filter, DWORD flags)
{
    DWORD err = GetLastError();
    HANDLE h;
    int obs = observing();
    h = real_FindFirstFileExW(pattern, lvl, data, op, filter, flags);
    if (obs) {
        char path[PW_TGT_LEN], det[PW_DET_LEN];
        pw_wide_to_utf8(pattern, path, sizeof(path));
        fmt(det, sizeof(det), "枚举目录（%s）",
            op == FindExSearchLimitToDirectories ? "仅目录" : "全部条目");
        pw_report(PW_CAT_FILE, PW_LVL_INFO, "FindFirstFileExW", path, det, 0, (int)GetLastError());
    }
    SetLastError(err);
    return h;
}

static BOOL WINAPI hook_SetFileAttributesW(LPCWSTR name, DWORD attr)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_SetFileAttributesW(name, attr);
    if (obs && (attr & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))) {
        char path[PW_TGT_LEN], det[PW_DET_LEN];
        pw_wide_to_utf8(name, path, sizeof(path));
        fmt(det, sizeof(det), "设置属性 0x%X%s%s", (unsigned)attr,
            (attr & FILE_ATTRIBUTE_HIDDEN) ? " | 隐藏" : "",
            (attr & FILE_ATTRIBUTE_SYSTEM) ? " | 系统" : "");
        pw_report(PW_CAT_FILE, PW_LVL_WARN, "SetFileAttributesW", path, det, 0, (int)GetLastError());
    }
    SetLastError(err);
    return ok;
}

/* Handles are recycled aggressively by the kernel; a stale cache entry would
 * mislabel an unrelated read, so drop it on close. Nothing is reported - this
 * hook exists purely to keep the mapping honest. */
static BOOL WINAPI hook_CloseHandle(HANDLE h)
{
    if (g_hcache_ready && !pw_suppressed()) hcache_del(h);
    return real_CloseHandle(h);
}

/* ----------------------------------------------------------- registry hooks */

static LSTATUS (WINAPI *real_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
static LSTATUS (WINAPI *real_RegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD,
                                              REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
static LSTATUS (WINAPI *real_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE *, DWORD);
static LSTATUS (WINAPI *real_RegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static LSTATUS (WINAPI *real_RegDeleteValueW)(HKEY, LPCWSTR);
static LSTATUS (WINAPI *real_RegDeleteKeyW)(HKEY, LPCWSTR);
static LSTATUS (WINAPI *real_RegDeleteKeyExW)(HKEY, LPCWSTR, REGSAM, DWORD);
/* ANSI variants: still common in older software, and each one forwards to its
 * wide counterpart internally (a direct call, not through any table we patch),
 * so hooking both does not double-report. */
static LSTATUS (WINAPI *real_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
static LSTATUS (WINAPI *real_RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD,
                                              REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
static LSTATUS (WINAPI *real_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
static LSTATUS (WINAPI *real_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static LSTATUS (WINAPI *real_RegDeleteValueA)(HKEY, LPCSTR);
static LSTATUS (WINAPI *real_RegDeleteKeyA)(HKEY, LPCSTR);

static void reg_value_detail(DWORD type, const BYTE *data, DWORD size, char *det, int n)
{
    const char *tn = "?";
    switch (type) {
    case REG_SZ:        tn = "REG_SZ"; break;
    case REG_EXPAND_SZ: tn = "REG_EXPAND_SZ"; break;
    case REG_DWORD:     tn = "REG_DWORD"; break;
    case REG_QWORD:     tn = "REG_QWORD"; break;
    case REG_BINARY:    tn = "REG_BINARY"; break;
    case REG_MULTI_SZ:  tn = "REG_MULTI_SZ"; break;
    }
    fmt(det, n, "类型 %s，%u 字节", tn, (unsigned)size);
    if (g_cfg.previews && data && size) {
        if ((type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) && size < 400) {
            char tmp[400];
            pw_wide_to_utf8((const wchar_t *)data, tmp, sizeof(tmp));
            pw_str_cat(det, n, "  值: ");
            pw_str_cat(det, n, tmp);
        } else if (type == REG_DWORD && size >= 4) {
            char tmp[64];
            fmt(tmp, sizeof(tmp), "  值: 0x%08X",
                (unsigned)*(const DWORD *)data);
            pw_str_cat(det, n, tmp);
        } else if (size <= 64) {
            char hex[260], tmp[300];
            pw_hex_ascii(data, (int)size, hex, sizeof(hex));
            fmt(tmp, sizeof(tmp), "  值: %s", hex);
            pw_str_cat(det, n, tmp);
        }
    }
}

static LSTATUS WINAPI hook_RegOpenKeyExW(HKEY root, LPCWSTR sub, DWORD opt,
                                         REGSAM sam, PHKEY out)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegOpenKeyExW(root, sub, opt, sam, out);
    if (obs && st == ERROR_SUCCESS) {
        char path[PW_TGT_LEN], det[PW_DET_LEN];
        reg_path_root(root, sub, path, sizeof(path));
        fmt(det, sizeof(det), "以%s权限打开", REGSAM_STR(sam));
        pw_report(PW_CAT_REG, PW_LVL_INFO, "RegOpenKeyExW", path, det, 0, 0);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegCreateKeyExW(HKEY root, LPCWSTR sub, DWORD res,
                                           LPWSTR cls, DWORD opt, REGSAM sam,
                                           LPSECURITY_ATTRIBUTES sa, PHKEY out,
                                           LPDWORD disp)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegCreateKeyExW(root, sub, res, cls, opt, sam, sa, out, disp);
    if (obs && st == ERROR_SUCCESS) {
        char path[PW_TGT_LEN], det[PW_DET_LEN];
        reg_path_root(root, sub, path, sizeof(path));
        fmt(det, sizeof(det), "创建/打开注册表键（%s）",
            (disp && *disp == REG_CREATED_NEW_KEY) ? "新建" : "已存在");
        pw_report(PW_CAT_REG, PW_LVL_WARN, "RegCreateKeyExW", path, det, 0, 0);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegSetValueExW(HKEY key, LPCWSTR name, DWORD res,
                                          DWORD type, const BYTE *data, DWORD size)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegSetValueExW(key, name, res, type, data, size);
    if (obs) {
        char keypath[300], name8[200], path[PW_TGT_LEN], det[PW_DET_LEN];
        reg_key_path(key, keypath, sizeof(keypath));
        pw_wide_to_utf8(name, name8, sizeof(name8));
        fmt(path, sizeof(path), "%s\\%s", keypath, name8[0] ? name8 : "(默认值)");
        reg_value_detail(type, data, size, det, sizeof(det));
        pw_report(PW_CAT_REG, PW_LVL_WARN, "RegSetValueExW", path, det, size, (int)st);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegQueryValueExW(HKEY key, LPCWSTR name, LPDWORD res,
                                            LPDWORD type, LPBYTE data, LPDWORD size)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegQueryValueExW(key, name, res, type, data, size);
    if (obs) {
        char keypath[300], name8[200], path[PW_TGT_LEN], det[PW_DET_LEN];
        reg_key_path(key, keypath, sizeof(keypath));
        pw_wide_to_utf8(name, name8, sizeof(name8));
        fmt(path, sizeof(path), "%s\\%s", keypath, name8[0] ? name8 : "(默认值)");
        if (st == ERROR_SUCCESS && type && data && size)
            reg_value_detail(*type, data, *size, det, sizeof(det));
        else
            fmt(det, sizeof(det), "查询失败（错误 %ld）", (long)st);
        pw_report(PW_CAT_REG, PW_LVL_INFO, "RegQueryValueExW", path, det,
                  size ? *size : 0, (int)st);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegDeleteValueW(HKEY key, LPCWSTR name)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegDeleteValueW(key, name);
    if (obs) {
        char keypath[300], name8[200], path[PW_TGT_LEN];
        reg_key_path(key, keypath, sizeof(keypath));
        pw_wide_to_utf8(name, name8, sizeof(name8));
        fmt(path, sizeof(path), "%s\\%s", keypath, name8[0] ? name8 : "(默认值)");
        pw_report(PW_CAT_REG, PW_LVL_WARN, "RegDeleteValueW", path,
                  st == ERROR_SUCCESS ? "已删除" : "删除失败", 0, (int)st);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegDeleteKeyW(HKEY key, LPCWSTR sub)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegDeleteKeyW(key, sub);
    if (obs) {
        char keypath[300], sub8[200], path[PW_TGT_LEN];
        reg_key_path(key, keypath, sizeof(keypath));
        pw_wide_to_utf8(sub, sub8, sizeof(sub8));
        fmt(path, sizeof(path), "%s\\%s", keypath, sub8);
        pw_report(PW_CAT_REG, PW_LVL_WARN, "RegDeleteKeyW", path,
                  st == ERROR_SUCCESS ? "已删除" : "删除失败", 0, (int)st);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegDeleteKeyExW(HKEY key, LPCWSTR sub, REGSAM sam, DWORD res)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegDeleteKeyExW(key, sub, sam, res);
    if (obs) {
        char keypath[300], sub8[200], path[PW_TGT_LEN];
        reg_key_path(key, keypath, sizeof(keypath));
        pw_wide_to_utf8(sub, sub8, sizeof(sub8));
        fmt(path, sizeof(path), "%s\\%s", keypath, sub8);
        pw_report(PW_CAT_REG, PW_LVL_WARN, "RegDeleteKeyExW", path,
                  st == ERROR_SUCCESS ? "已删除（含子键）" : "删除失败", 0, (int)st);
    }
    SetLastError(err);
    return st;
}

/* ---------------------------------------------------- registry hooks (ANSI) */

static LSTATUS WINAPI hook_RegOpenKeyExA(HKEY root, LPCSTR sub, DWORD opt,
                                         REGSAM sam, PHKEY out)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegOpenKeyExA(root, sub, opt, sam, out);
    if (obs && st == ERROR_SUCCESS) {
        char path[PW_TGT_LEN], det[PW_DET_LEN];
        reg_path_root_a(root, sub, path, sizeof(path));
        fmt(det, sizeof(det), "以%s权限打开（ANSI 接口）", REGSAM_STR(sam));
        pw_report(PW_CAT_REG, PW_LVL_INFO, "RegOpenKeyExA", path, det, 0, 0);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegCreateKeyExA(HKEY root, LPCSTR sub, DWORD res,
                                           LPSTR cls, DWORD opt, REGSAM sam,
                                           LPSECURITY_ATTRIBUTES sa, PHKEY out,
                                           LPDWORD disp)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegCreateKeyExA(root, sub, res, cls, opt, sam, sa, out, disp);
    if (obs && st == ERROR_SUCCESS) {
        char path[PW_TGT_LEN], det[PW_DET_LEN];
        reg_path_root_a(root, sub, path, sizeof(path));
        fmt(det, sizeof(det), "创建/打开注册表键（%s，ANSI 接口）",
            (disp && *disp == REG_CREATED_NEW_KEY) ? "新建" : "已存在");
        pw_report(PW_CAT_REG, PW_LVL_WARN, "RegCreateKeyExA", path, det, 0, 0);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegSetValueExA(HKEY key, LPCSTR name, DWORD res,
                                          DWORD type, const BYTE *data, DWORD size)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegSetValueExA(key, name, res, type, data, size);
    if (obs) {
        char keypath[300], name8[200], path[PW_TGT_LEN], det[PW_DET_LEN];
        reg_key_path(key, keypath, sizeof(keypath));
        pw_ansi_to_utf8(name, name8, sizeof(name8));
        fmt(path, sizeof(path), "%s\\%s", keypath, name8[0] ? name8 : "(默认值)");
        reg_value_detail(type, data, size, det, sizeof(det));
        pw_report(PW_CAT_REG, PW_LVL_WARN, "RegSetValueExA", path, det, size, (int)st);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegQueryValueExA(HKEY key, LPCSTR name, LPDWORD res,
                                            LPDWORD type, LPBYTE data, LPDWORD size)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegQueryValueExA(key, name, res, type, data, size);
    if (obs) {
        char keypath[300], name8[200], path[PW_TGT_LEN], det[PW_DET_LEN];
        reg_key_path(key, keypath, sizeof(keypath));
        pw_ansi_to_utf8(name, name8, sizeof(name8));
        fmt(path, sizeof(path), "%s\\%s", keypath, name8[0] ? name8 : "(默认值)");
        if (st == ERROR_SUCCESS && type && data && size)
            reg_value_detail(*type, data, *size, det, sizeof(det));
        else
            fmt(det, sizeof(det), "查询失败（错误 %ld）", (long)st);
        pw_report(PW_CAT_REG, PW_LVL_INFO, "RegQueryValueExA", path, det,
                  size ? *size : 0, (int)st);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegDeleteValueA(HKEY key, LPCSTR name)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegDeleteValueA(key, name);
    if (obs) {
        char keypath[300], name8[200], path[PW_TGT_LEN];
        reg_key_path(key, keypath, sizeof(keypath));
        pw_ansi_to_utf8(name, name8, sizeof(name8));
        fmt(path, sizeof(path), "%s\\%s", keypath, name8[0] ? name8 : "(默认值)");
        pw_report(PW_CAT_REG, PW_LVL_WARN, "RegDeleteValueA", path,
                  st == ERROR_SUCCESS ? "已删除" : "删除失败", 0, (int)st);
    }
    SetLastError(err);
    return st;
}

static LSTATUS WINAPI hook_RegDeleteKeyA(HKEY key, LPCSTR sub)
{
    DWORD err = GetLastError();
    LSTATUS st;
    int obs = observing();
    st = real_RegDeleteKeyA(key, sub);
    if (obs) {
        char sub8[200], path[PW_TGT_LEN];
        pw_ansi_to_utf8(sub, sub8, sizeof(sub8));
        fmt(path, sizeof(path), "%s\\%s", root_key_name(key), sub8);
        pw_report(PW_CAT_REG, PW_LVL_WARN, "RegDeleteKeyA", path,
                  st == ERROR_SUCCESS ? "已删除" : "删除失败", 0, (int)st);
    }
    SetLastError(err);
    return st;
}

/* -------------------------------------------------------------- socket hooks */

static SOCKET (WSAAPI *real_socket)(int, int, int);
static int    (WSAAPI *real_connect)(SOCKET, const struct sockaddr *, int);
static int    (WSAAPI *real_WSAConnect)(SOCKET, const struct sockaddr *, int,
                                        LPWSABUF, LPWSABUF, LPQOS, LPQOS);
static int    (WSAAPI *real_send)(SOCKET, const char *, int, int);
static int    (WSAAPI *real_recv)(SOCKET, char *, int, int);
static int    (WSAAPI *real_WSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
                                     LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static int    (WSAAPI *real_WSARecv)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
                                     LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static int    (WSAAPI *real_sendto)(SOCKET, const char *, int, int,
                                    const struct sockaddr *, int);
static int    (WSAAPI *real_recvfrom)(SOCKET, char *, int, int, struct sockaddr *, int *);
static int    (WSAAPI *real_closesocket)(SOCKET);
static int    (WSAAPI *real_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *);
static INT    (WSAAPI *real_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW *, PADDRINFOW *);
static struct hostent *(WSAAPI *real_gethostbyname)(const char *);

static const char *sock_type_str(int t)
{
    switch (t) {
    case SOCK_STREAM: return "SOCK_STREAM";
    case SOCK_DGRAM:  return "SOCK_DGRAM";
    case SOCK_RAW:    return "SOCK_RAW";
    default:          return "其它";
    }
}

static SOCKET WSAAPI hook_socket(int af, int type, int proto)
{
    DWORD err = GetLastError();
    SOCKET s;
    int obs = observing();
    s = real_socket(af, type, proto);
    if (obs && s != INVALID_SOCKET) {
        char det[PW_DET_LEN];
        fmt(det, sizeof(det), "协议族 %s，类型 %s，协议 %d",
            af == AF_INET ? "IPv4" : af == AF_INET6 ? "IPv6" : "其它",
            sock_type_str(type), proto);
        pw_report(PW_CAT_NET, (type == SOCK_RAW) ? PW_LVL_SUSPECT : PW_LVL_INFO,
                  "socket", "(新建套接字)", det, 0, (int)s);
    }
    SetLastError(err);
    return s;
}

static int WSAAPI hook_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_connect(s, name, namelen);
    if (obs) {
        char addr[128], det[PW_DET_LEN];
        pw_format_sockaddr(name, namelen, addr, sizeof(addr));
        fmt(det, sizeof(det), "%s连接%s", rc == 0 ? "" : "尝试", addr);
        pw_report(PW_CAT_NET,
                  pw_sockaddr_is_local(name) ? PW_LVL_INFO : PW_LVL_WARN,
                  "connect", addr, det, 0, rc);
    }
    SetLastError(err);
    return rc;
}

static int WSAAPI hook_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen,
                                  LPWSABUF in, LPWSABUF out, LPQOS q1, LPQOS q2)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_WSAConnect(s, name, namelen, in, out, q1, q2);
    if (obs) {
        char addr[128], det[PW_DET_LEN];
        pw_format_sockaddr(name, namelen, addr, sizeof(addr));
        fmt(det, sizeof(det), "%s连接%s", rc == 0 ? "" : "尝试", addr);
        pw_report(PW_CAT_NET,
                  pw_sockaddr_is_local(name) ? PW_LVL_INFO : PW_LVL_WARN,
                  "WSAConnect", addr, det, 0, rc);
    }
    SetLastError(err);
    return rc;
}

static int WSAAPI hook_send(SOCKET s, const char *buf, int len, int flags)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_send(s, buf, len, flags);
    if (obs && rc > 0) {
        char det[PW_DET_LEN];
        preview(buf, (unsigned)rc, det, sizeof(det));
        if (!det[0]) fmt(det, sizeof(det), "发送 %d 字节", rc);
        pw_report(PW_CAT_NET, PW_LVL_INFO, "send", "(套接字发送)", det,
                  (unsigned)rc, rc);
    }
    SetLastError(err);
    return rc;
}

static int WSAAPI hook_recv(SOCKET s, char *buf, int len, int flags)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_recv(s, buf, len, flags);
    if (obs && rc > 0) {
        char det[PW_DET_LEN];
        preview(buf, (unsigned)rc, det, sizeof(det));
        if (!det[0]) fmt(det, sizeof(det), "接收 %d 字节", rc);
        pw_report(PW_CAT_NET, PW_LVL_INFO, "recv", "(套接字接收)", det,
                  (unsigned)rc, rc);
    }
    SetLastError(err);
    return rc;
}

static int WSAAPI hook_WSASend(SOCKET s, LPWSABUF bufs, DWORD nbufs, LPDWORD sent,
                               DWORD flags, LPWSAOVERLAPPED ov,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE fn)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_WSASend(s, bufs, nbufs, sent, flags, ov, fn);
    if (obs && bufs && nbufs) {
        DWORD total = 0, i;
        char det[PW_DET_LEN];
        for (i = 0; i < nbufs; i++) total += bufs[i].len;
        preview(bufs[0].buf, bufs[0].len, det, sizeof(det));
        if (!det[0]) fmt(det, sizeof(det), "发送 %u 字节（%u 个缓冲）", (unsigned)total, (unsigned)nbufs);
        pw_report(PW_CAT_NET, PW_LVL_INFO, "WSASend", "(套接字发送)", det, total, rc);
    }
    SetLastError(err);
    return rc;
}

static int WSAAPI hook_WSARecv(SOCKET s, LPWSABUF bufs, DWORD nbufs, LPDWORD got,
                               LPDWORD flags, LPWSAOVERLAPPED ov,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE fn)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_WSARecv(s, bufs, nbufs, got, flags, ov, fn);
    if (obs && bufs && nbufs && got && *got) {
        char det[PW_DET_LEN];
        preview(bufs[0].buf, *got, det, sizeof(det));
        if (!det[0]) fmt(det, sizeof(det), "接收 %u 字节", (unsigned)*got);
        pw_report(PW_CAT_NET, PW_LVL_INFO, "WSARecv", "(套接字接收)", det, *got, rc);
    }
    SetLastError(err);
    return rc;
}

static int WSAAPI hook_sendto(SOCKET s, const char *buf, int len, int flags,
                              const struct sockaddr *to, int tolen)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_sendto(s, buf, len, flags, to, tolen);
    if (obs && rc > 0) {
        char addr[128], det[PW_DET_LEN];
        pw_format_sockaddr(to, tolen, addr, sizeof(addr));
        preview(buf, (unsigned)rc, det, sizeof(det));
        if (!det[0]) fmt(det, sizeof(det), "发送 %d 字节", rc);
        pw_str_cat(det, sizeof(det), "  -> ");
        pw_str_cat(det, sizeof(det), addr);
        pw_report(PW_CAT_NET, pw_sockaddr_is_local(to) ? PW_LVL_INFO : PW_LVL_WARN,
                  "sendto", addr, det, (unsigned)rc, rc);
    }
    SetLastError(err);
    return rc;
}

static int WSAAPI hook_recvfrom(SOCKET s, char *buf, int len, int flags,
                                struct sockaddr *from, int *fromlen)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_recvfrom(s, buf, len, flags, from, fromlen);
    if (obs && rc > 0) {
        char addr[128], det[PW_DET_LEN];
        pw_format_sockaddr(from, fromlen ? *fromlen : 0, addr, sizeof(addr));
        preview(buf, (unsigned)rc, det, sizeof(det));
        if (!det[0]) fmt(det, sizeof(det), "接收 %d 字节", rc);
        pw_str_cat(det, sizeof(det), "  <- ");
        pw_str_cat(det, sizeof(det), addr);
        pw_report(PW_CAT_NET, PW_LVL_INFO, "recvfrom", addr, det, (unsigned)rc, rc);
    }
    SetLastError(err);
    return rc;
}

static int WSAAPI hook_closesocket(SOCKET s)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_closesocket(s);
    if (obs)
        pw_report(PW_CAT_NET, PW_LVL_INFO, "closesocket", "(关闭套接字)",
                  rc == 0 ? "已关闭" : "关闭失败", 0, rc);
    SetLastError(err);
    return rc;
}

static int WSAAPI hook_getaddrinfo(PCSTR node, PCSTR service,
                                   const ADDRINFOA *hints, PADDRINFOA *res)
{
    DWORD err = GetLastError();
    int rc;
    int obs = observing();
    rc = real_getaddrinfo(node, service, hints, res);
    if (obs) {
        char det[PW_DET_LEN];
        fmt(det, sizeof(det), "解析域名%s%s", service ? " 端口 " : "", service ? service : "");
        pw_report(PW_CAT_NET, PW_LVL_WARN, "getaddrinfo",
                  node ? node : "(空)", det, 0, rc);
    }
    SetLastError(err);
    return rc;
}

static INT WSAAPI hook_GetAddrInfoW(PCWSTR node, PCWSTR service,
                                    const ADDRINFOW *hints, PADDRINFOW *res)
{
    DWORD err = GetLastError();
    INT rc;
    int obs = observing();
    char host[256];
    rc = real_GetAddrInfoW(node, service, hints, res);
    if (obs) {
        char det[PW_DET_LEN];
        pw_wide_to_utf8(node, host, sizeof(host));
        if (service) {
            char svc[64];
            pw_wide_to_utf8(service, svc, sizeof(svc));
            fmt(det, sizeof(det), "解析域名，端口 %s", svc);
        } else {
            pw_str_copy(det, sizeof(det), "解析域名");
        }
        pw_report(PW_CAT_NET, PW_LVL_WARN, "GetAddrInfoW",
                  host[0] ? host : "(空)", det, 0, rc);
    }
    SetLastError(err);
    return rc;
}

static struct hostent *WSAAPI hook_gethostbyname(const char *name)
{
    DWORD err = GetLastError();
    struct hostent *he;
    int obs = observing();
    he = real_gethostbyname(name);
    if (obs)
        pw_report(PW_CAT_NET, PW_LVL_WARN, "gethostbyname",
                  name ? name : "(空)", "解析域名（旧接口）", 0, he ? 0 : -1);
    SetLastError(err);
    return he;
}

/* ---------------------------------------------------------------- HTTP hooks */

static HINTERNET (WINAPI *real_InternetOpenW)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
static HINTERNET (WINAPI *real_InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
static HINTERNET (WINAPI *real_InternetConnectW)(HINTERNET, LPCWSTR, INTERNET_PORT,
                                                 LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
static HINTERNET (WINAPI *real_InternetOpenUrlW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD,
                                                 DWORD, DWORD_PTR);
static HINTERNET (WINAPI *real_HttpOpenRequestW)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR,
                                                 LPCWSTR, LPCWSTR *, DWORD, DWORD_PTR);
static BOOL (WINAPI *real_HttpSendRequestW)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
static BOOL (WINAPI *real_InternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
static BOOL (WINAPI *real_InternetSetOptionW)(HINTERNET, DWORD, LPVOID, DWORD);

static HINTERNET WINAPI hook_InternetOpenW(LPCWSTR agent, DWORD access, LPCWSTR proxy,
                                           LPCWSTR bypass, DWORD flags)
{
    DWORD err = GetLastError();
    HINTERNET h;
    int obs = observing();
    h = real_InternetOpenW(agent, access, proxy, bypass, flags);
    if (obs) {
        char ua[300], px[300], det[PW_DET_LEN];
        pw_wide_to_utf8(agent, ua, sizeof(ua));
        pw_wide_to_utf8(proxy, px, sizeof(px));
        fmt(det, sizeof(det), "User-Agent: %s", ua[0] ? ua : "(默认)");
        if (access == INTERNET_OPEN_TYPE_PROXY) {
            pw_str_cat(det, sizeof(det), "  |  显式使用代理: ");
            pw_str_cat(det, sizeof(det), px[0] ? px : "(未提供)");
        } else if (access == INTERNET_OPEN_TYPE_PRECONFIG) {
            pw_str_cat(det, sizeof(det), "  |  使用系统代理配置");
        }
        pw_report(PW_CAT_HTTP, PW_LVL_INFO, "InternetOpenW",
                  ua[0] ? ua : "(WinINet 会话)", det, 0, 0);
    }
    SetLastError(err);
    return h;
}

static HINTERNET WINAPI hook_InternetOpenA(LPCSTR agent, DWORD access, LPCSTR proxy,
                                           LPCSTR bypass, DWORD flags)
{
    DWORD err = GetLastError();
    HINTERNET h;
    int obs = observing();
    h = real_InternetOpenA(agent, access, proxy, bypass, flags);
    if (obs) {
        char det[PW_DET_LEN];
        fmt(det, sizeof(det), "User-Agent: %s", agent ? agent : "(默认)");
        if (access == INTERNET_OPEN_TYPE_PROXY) {
            pw_str_cat(det, sizeof(det), "  |  显式使用代理: ");
            pw_str_cat(det, sizeof(det), proxy ? proxy : "(未提供)");
        } else if (access == INTERNET_OPEN_TYPE_PRECONFIG) {
            pw_str_cat(det, sizeof(det), "  |  使用系统代理配置");
        }
        pw_report(PW_CAT_HTTP, PW_LVL_INFO, "InternetOpenA",
                  agent ? agent : "(WinINet 会话)", det, 0, 0);
    }
    SetLastError(err);
    return h;
}

static HINTERNET WINAPI hook_InternetConnectW(HINTERNET net, LPCWSTR server,
                                              INTERNET_PORT port, LPCWSTR user,
                                              LPCWSTR pass, DWORD service,
                                              DWORD flags, DWORD_PTR ctx)
{
    DWORD err = GetLastError();
    HINTERNET h;
    int obs = observing();
    h = real_InternetConnectW(net, server, port, user, pass, service, flags, ctx);
    if (obs) {
        char srv[256], usr[128], det[PW_DET_LEN], tgt[PW_TGT_LEN];
        pw_wide_to_utf8(server, srv, sizeof(srv));
        pw_wide_to_utf8(user, usr, sizeof(usr));
        fmt(tgt, sizeof(tgt), "%s:%u", srv, (unsigned)port);
        fmt(det, sizeof(det), "%s连接，服务类型 %s%s%s",
            h ? "" : "尝试",
            service == INTERNET_SERVICE_HTTP ? "HTTP" :
            service == INTERNET_SERVICE_FTP ? "FTP" : "其它",
            usr[0] ? "，用户名 " : "", usr);
        pw_report(PW_CAT_HTTP, PW_LVL_INFO, "InternetConnectW", tgt, det, 0, 0);
    }
    SetLastError(err);
    return h;
}

static HINTERNET WINAPI hook_InternetOpenUrlW(HINTERNET net, LPCWSTR url, LPCWSTR headers,
                                              DWORD hlen, DWORD flags, DWORD_PTR ctx)
{
    DWORD err = GetLastError();
    HINTERNET h;
    int obs = observing();
    h = real_InternetOpenUrlW(net, url, headers, hlen, flags, ctx);
    if (obs) {
        char u[PW_TGT_LEN], det[PW_DET_LEN];
        pw_wide_to_utf8(url, u, sizeof(u));
        pw_str_copy(det, sizeof(det), "直接打开 URL 并读取响应");
        pw_report(PW_CAT_HTTP, PW_LVL_WARN, "InternetOpenUrlW",
                  u[0] ? u : "(空)", det, 0, 0);
    }
    SetLastError(err);
    return h;
}

static HINTERNET WINAPI hook_HttpOpenRequestW(HINTERNET conn, LPCWSTR verb, LPCWSTR object,
                                              LPCWSTR version, LPCWSTR referrer,
                                              LPCWSTR *types, DWORD flags, DWORD_PTR ctx)
{
    DWORD err = GetLastError();
    HINTERNET h;
    int obs = observing();
    h = real_HttpOpenRequestW(conn, verb, object, version, referrer, types, flags, ctx);
    if (obs) {
        char v[32], o[PW_TGT_LEN], det[PW_DET_LEN];
        pw_wide_to_utf8(verb, v, sizeof(v));
        pw_wide_to_utf8(object, o, sizeof(o));
        fmt(det, sizeof(det), "%s %s%s%s", v[0] ? v : "GET", o,
            (flags & INTERNET_FLAG_SECURE) ? "  |  HTTPS" : "  |  明文 HTTP",
            (flags & INTERNET_FLAG_NO_CACHE_WRITE) ? "  |  不写缓存" : "");
        pw_report(PW_CAT_HTTP, PW_LVL_INFO, "HttpOpenRequestW",
                  o[0] ? o : "/", det, 0, 0);
    }
    SetLastError(err);
    return h;
}

static BOOL WINAPI hook_HttpSendRequestW(HINTERNET req, LPCWSTR headers, DWORD hlen,
                                         LPVOID opt, DWORD optlen)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_HttpSendRequestW(req, headers, hlen, opt, optlen);
    if (obs) {
        char det[PW_DET_LEN];
        if (headers) {
            char h8[600];
            pw_wide_to_utf8(headers, h8, sizeof(h8));
            summarise_headers(h8, det, sizeof(det));
        }
        if (!det[0]) pw_str_copy(det, sizeof(det), "发送 HTTP 请求");
        pw_report(PW_CAT_HTTP, ok ? PW_LVL_INFO : PW_LVL_WARN,
                  "HttpSendRequestW", "(HTTP 请求)", det, optlen, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_InternetReadFile(HINTERNET req, LPVOID buf, DWORD toRead,
                                         LPDWORD got)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_InternetReadFile(req, buf, toRead, got);
    if (obs) {
        DWORD n = (ok && got) ? *got : 0;
        char det[PW_DET_LEN];
        if (n) {
            preview(buf, n, det, sizeof(det));
            if (!det[0]) fmt(det, sizeof(det), "读取响应体 %u 字节", (unsigned)n);
        } else {
            pw_str_copy(det, sizeof(det), ok ? "响应结束" : "读取失败");
        }
        pw_report(PW_CAT_HTTP, PW_LVL_INFO, "InternetReadFile",
                  "(HTTP 响应)", det, n, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_InternetSetOptionW(HINTERNET h, DWORD opt, LPVOID buf, DWORD len)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_InternetSetOptionW(h, opt, buf, len);
    if (obs) {
        char det[PW_DET_LEN], tgt[128];
        fmt(tgt, sizeof(tgt), "WinINet 选项 %u", (unsigned)opt);
        switch (opt) {
        case INTERNET_OPTION_PROXY:
            pw_str_copy(det, sizeof(det), "修改代理设置");
            if (buf && len && ((LPVOID *)buf)[0] == NULL) {
                pw_str_cat(det, sizeof(det), "（清除代理）");
            }
            pw_report(PW_CAT_HTTP, PW_LVL_SUSPECT, "InternetSetOptionW", tgt, det, len, ok);
            break;
        case INTERNET_OPTION_SETTINGS_CHANGED:
        case INTERNET_OPTION_PROXY_SETTINGS_CHANGED:
        case INTERNET_OPTION_REFRESH:
            pw_str_copy(det, sizeof(det), "刷新代理配置缓存");
            pw_report(PW_CAT_HTTP, PW_LVL_WARN, "InternetSetOptionW", tgt, det, len, ok);
            break;
        case INTERNET_OPTION_USER_AGENT:
            pw_str_copy(det, sizeof(det), "设置 User-Agent");
            pw_report(PW_CAT_HTTP, PW_LVL_INFO, "InternetSetOptionW", tgt, det, len, ok);
            break;
        default:
            break;   /* everything else is noise */
        }
    }
    SetLastError(err);
    return ok;
}

/* -------------------------------------------------------- process hooks */

static BOOL (WINAPI *real_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                          LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                          LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
static BOOL (WINAPI *real_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                                          LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                          LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
static UINT (WINAPI *real_WinExec)(LPCSTR, UINT);
static BOOL (WINAPI *real_ShellExecuteExW)(SHELLEXECUTEINFOW *);
static BOOL (WINAPI *real_CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                                LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                                LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static void log_process(const char *api, const wchar_t *app, const wchar_t *cmd,
                        DWORD flags, BOOL ok, DWORD pid)
{
    char a8[200], c8[PW_TGT_LEN], det[PW_DET_LEN];
    const char *shown;

    pw_wide_to_utf8(app, a8, sizeof(a8));
    pw_wide_to_utf8(cmd, c8, sizeof(c8));
    shown = c8[0] ? c8 : a8;
    if (!shown[0]) shown = "(空命令行)";

    fmt(det, sizeof(det), "%s新进程 PID %lu%s%s%s%s",
        ok ? "" : "尝试创建", (unsigned long)pid,
        (flags & CREATE_SUSPENDED) ? "  |  挂起启动" : "",
        (flags & DETACHED_PROCESS) ? "  |  无控制台" : "",
        (flags & CREATE_NO_WINDOW) ? "  |  隐藏窗口" : "",
        (flags & CREATE_NEW_CONSOLE) ? "  |  新控制台" : "");
    pw_report(PW_CAT_PROC, PW_LVL_WARN, api, shown, det, 0, ok ? 0 : -1);
}

static BOOL WINAPI hook_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                                       LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
                                       LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si,
                                       LPPROCESS_INFORMATION pi)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_CreateProcessW(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    if (obs)
        log_process("CreateProcessW", app, cmd, flags, ok,
                    (ok && pi) ? pi->dwProcessId : 0);
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
                                       LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
                                       LPVOID env, LPCSTR dir, LPSTARTUPINFOA si,
                                       LPPROCESS_INFORMATION pi)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_CreateProcessA(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    if (obs) {
        wchar_t wa[300], wc[PW_TGT_LEN];
        if (app) pw_utf8_to_wide(app, wa, 300); else wa[0] = 0;
        if (cmd) pw_utf8_to_wide(cmd, wc, PW_TGT_LEN); else wc[0] = 0;
        log_process("CreateProcessA", wa, wc, flags, ok,
                    (ok && pi) ? pi->dwProcessId : 0);
    }
    SetLastError(err);
    return ok;
}

static UINT WINAPI hook_WinExec(LPCSTR cmd, UINT show)
{
    DWORD err = GetLastError();
    UINT rc;
    int obs = observing();
    rc = real_WinExec(cmd, show);
    if (obs) {
        char det[PW_DET_LEN];
        fmt(det, sizeof(det), "以 WinExec 启动，显示方式 %u%s", show,
            (show == SW_HIDE) ? "  |  隐藏窗口" : "");
        pw_report(PW_CAT_PROC, PW_LVL_WARN, "WinExec",
                  cmd ? cmd : "(空)", det, 0, (int)rc);
    }
    SetLastError(err);
    return rc;
}

static BOOL WINAPI hook_ShellExecuteExW(SHELLEXECUTEINFOW *info)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_ShellExecuteExW(info);
    if (obs && info) {
        char f[400], p[300], v[64], det[PW_DET_LEN];
        pw_wide_to_utf8(info->lpFile, f, sizeof(f));
        pw_wide_to_utf8(info->lpParameters, p, sizeof(p));
        pw_wide_to_utf8(info->lpVerb, v, sizeof(v));
        if (p[0]) { pw_str_cat(f, sizeof(f), " "); pw_str_cat(f, sizeof(f), p); }
        fmt(det, sizeof(det), "ShellExecute 动词 %s%s",
            v[0] ? v : "open", (info->nShow == SW_HIDE) ? "  |  隐藏窗口" : "");
        pw_report(PW_CAT_PROC, PW_LVL_WARN, "ShellExecuteExW",
                  f[0] ? f : "(空)", det, 0, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_CreateProcessAsUserW(HANDLE tok, LPCWSTR app, LPWSTR cmd,
                                             LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                             BOOL inherit, DWORD flags, LPVOID env,
                                             LPCWSTR dir, LPSTARTUPINFOW si,
                                             LPPROCESS_INFORMATION pi)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_CreateProcessAsUserW(tok, app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    if (obs)
        log_process("CreateProcessAsUserW", app, cmd, flags, ok,
                    (ok && pi) ? pi->dwProcessId : 0);
    SetLastError(err);
    return ok;
}

/* --------------------------------------------------------- module hooks */

static HMODULE (WINAPI *real_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
static HMODULE (WINAPI *real_LoadLibraryW)(LPCWSTR);
static HMODULE (WINAPI *real_LoadLibraryA)(LPCSTR);
static FARPROC (WINAPI *real_GetProcAddress)(HMODULE, LPCSTR);

/* Names a piece of malware usually reaches for dynamically. */
static const char *const SENSITIVE_PROC[] = {
    "VirtualAlloc", "VirtualProtect", "VirtualAllocEx", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext",
    "QueueUserAPC", "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState",
    "URLDownloadToFile", "ShellExecute", "WinExec", "CreateProcess",
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt",
    "MiniDumpWriteDump", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "CreateService", "OpenSCManager",
    "RegSetValueEx", "RegCreateKeyEx", "CreateFile", "WriteFile", "DeleteFile",
    "InternetOpen", "InternetReadFile", "HttpSendRequest", "WinHttpOpen",
    "WinHttpSendRequest", "connect", "send", "recv", "socket",
    "GetComputerName", "GetUserName", "GetVolumeInformation", "FindFirstFile",
    "EnumProcesses", "Process32First", "Thread32First", "CreateToolhelp32Snapshot",
    "BitBlt", "GetDC", "SetFileAttributes", "MoveFileEx", "CopyFile",
    "TerminateProcess", "ExitWindowsEx", "InitiateSystemShutdown",
};
#define N_SENSITIVE_PROC ((int)(sizeof(SENSITIVE_PROC) / sizeof(SENSITIVE_PROC[0])))

static int proc_is_sensitive(const char *name)
{
    int i;
    for (i = 0; i < N_SENSITIVE_PROC; i++)
        if (pw_streqi(name, SENSITIVE_PROC[i])) return 1;
    return 0;
}

static void log_module_load(const char *api, const wchar_t *name, HMODULE mod, int ok)
{
    char path8[MAX_PATH], det[PW_DET_LEN];
    int fromUserDir = 0;

    pw_wide_to_utf8(name, path8, sizeof(path8));
    if (ok && mod) {
        char full[MAX_PATH];
        if (GetModuleFileNameA(mod, full, sizeof(full))) {
            fromUserDir = pw_contains_i(full, "\\appdata\\") ||
                          pw_contains_i(full, "\\temp\\") ||
                          pw_contains_i(full, "\\downloads\\") ||
                          pw_contains_i(full, "\\users\\public\\");
            pw_str_copy(path8, sizeof(path8), full);
        }
    }
    fmt(det, sizeof(det), "%s加载模块%s", ok ? "" : "尝试",
        fromUserDir ? "  |  来自用户可写目录" : "");
    pw_report(PW_CAT_MOD, fromUserDir ? PW_LVL_SUSPECT : PW_LVL_INFO,
              api, path8[0] ? path8 : "(空)", det, 0, ok ? 0 : -1);
}

static HMODULE WINAPI hook_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    DWORD err = GetLastError();
    HMODULE m;
    int obs = observing();
    m = real_LoadLibraryExW(name, file, flags);
    if (obs) log_module_load("LoadLibraryExW", name, m, m != NULL);
    /* A module that appeared after us still holds the untouched addresses. */
    if (m && !pw_suppressed()) pw_hooks_on_module_load(m);
    SetLastError(err);
    return m;
}

static HMODULE WINAPI hook_LoadLibraryW(LPCWSTR name)
{
    DWORD err = GetLastError();
    HMODULE m;
    int obs = observing();
    m = real_LoadLibraryW(name);
    if (obs) log_module_load("LoadLibraryW", name, m, m != NULL);
    if (m && !pw_suppressed()) pw_hooks_on_module_load(m);
    SetLastError(err);
    return m;
}

static HMODULE WINAPI hook_LoadLibraryA(LPCSTR name)
{
    DWORD err = GetLastError();
    HMODULE m;
    int obs = observing();
    wchar_t w[400];
    m = real_LoadLibraryA(name);
    if (name) pw_utf8_to_wide(name, w, 400); else w[0] = 0;
    if (obs) log_module_load("LoadLibraryA", w, m, m != NULL);
    if (m && !pw_suppressed()) pw_hooks_on_module_load(m);
    SetLastError(err);
    return m;
}

/* Resolving a function by name is how malware avoids appearing in the import
 * table, so it is worth recording - but only for names that matter, otherwise
 * the log drowns in ordinary loader chatter.
 *
 * This hook is also how coverage is kept after dropping export-table patching:
 * when the caller asks for an address we hook, it gets our hook instead. The
 * call still reaches the real function (we forward to it), and it becomes
 * visible in the log. */
static FARPROC WINAPI hook_GetProcAddress(HMODULE mod, LPCSTR name)
{
    DWORD err = GetLastError();
    FARPROC p;
    int obs = observing();

    p = real_GetProcAddress(mod, name);

    if (p) {
        void *replacement = pw_hooks_redirect((void *)p);
        if (replacement) {
            if (obs) {
                char det[PW_DET_LEN];
                fmt(det, sizeof(det), "动态解析的函数已被监控接管（真实地址 0x%p）",
                    (void *)p);
                pw_report(PW_CAT_MOD, PW_LVL_WARN, "GetProcAddress",
                          name, det, 0, 0);
            }
            SetLastError(err);
            return (FARPROC)replacement;
        }
    }

    if (obs && name && (g_cfg.verbose || proc_is_sensitive(name))) {
        char det[PW_DET_LEN];
        fmt(det, sizeof(det), "动态解析函数地址 0x%p%s", (void *)p,
            p ? "" : "（失败）");
        pw_report(PW_CAT_MOD, PW_LVL_INFO, "GetProcAddress",
                  name, det, 0, p ? 0 : -1);
    }
    SetLastError(err);
    return p;
}

/* --------------------------------------------------------- memory hooks */

static LPVOID (WINAPI *real_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
static BOOL   (WINAPI *real_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
static LPVOID (WINAPI *real_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
static BOOL   (WINAPI *real_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
static BOOL   (WINAPI *real_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, PSIZE_T);
static HANDLE (WINAPI *real_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                                LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static HANDLE (WINAPI *real_OpenProcess)(DWORD, BOOL, DWORD);
static BOOL   (WINAPI *real_QueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);

static int prot_has_exec(DWORD p)
{
    return (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                 PAGE_EXECUTE_WRITECOPY)) != 0;
}

static void prot_str(DWORD p, char *out, int n)
{
    out[0] = 0;
    if (p & PAGE_NOACCESS)          pw_str_cat(out, n, "PAGE_NOACCESS ");
    if (p & PAGE_READONLY)          pw_str_cat(out, n, "PAGE_READONLY ");
    if (p & PAGE_READWRITE)         pw_str_cat(out, n, "PAGE_READWRITE ");
    if (p & PAGE_WRITECOPY)         pw_str_cat(out, n, "PAGE_WRITECOPY ");
    if (p & PAGE_EXECUTE)           pw_str_cat(out, n, "PAGE_EXECUTE ");
    if (p & PAGE_EXECUTE_READ)      pw_str_cat(out, n, "PAGE_EXECUTE_READ ");
    if (p & PAGE_EXECUTE_READWRITE) pw_str_cat(out, n, "PAGE_EXECUTE_READWRITE ");
    if (p & PAGE_EXECUTE_WRITECOPY) pw_str_cat(out, n, "PAGE_EXECUTE_WRITECOPY ");
    if (p & PAGE_GUARD)             pw_str_cat(out, n, "| PAGE_GUARD ");
    if (!out[0]) fmt(out, n, "0x%X", (unsigned)p);
}

static LPVOID WINAPI hook_VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD prot)
{
    DWORD err = GetLastError();
    LPVOID p;
    int obs = observing();
    p = real_VirtualAlloc(addr, size, type, prot);
    /* Allocation is far too common to log in full; only executable requests. */
    if (obs && prot_has_exec(prot)) {
        char ps[160], det[PW_DET_LEN];
        prot_str(prot, ps, sizeof(ps));
        fmt(det, sizeof(det), "申请 %llu 字节，权限 %s", (unsigned long long)size, ps);
        pw_report(PW_CAT_MEM,
                  (prot & PAGE_EXECUTE_READWRITE) ? PW_LVL_SUSPECT : PW_LVL_WARN,
                  "VirtualAlloc", (p ? "已分配" : "分配失败"), det, (unsigned)size, 0);
    }
    SetLastError(err);
    return p;
}

static BOOL WINAPI hook_VirtualProtect(LPVOID addr, SIZE_T size, DWORD prot, PDWORD old)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    DWORD was = 0;
    if (old) was = *old;
    ok = real_VirtualProtect(addr, size, prot, old);
    if (obs && (prot_has_exec(prot) || prot_has_exec(was))) {
        char a[160], b[160], det[PW_DET_LEN];
        prot_str(was, a, sizeof(a));
        prot_str(prot, b, sizeof(b));
        fmt(det, sizeof(det), "%s -> %s，%llu 字节", a, b, (unsigned long long)size);
        pw_report(PW_CAT_MEM, PW_LVL_WARN, "VirtualProtect", "(本进程内存)", det,
                  (unsigned)size, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

static LPVOID WINAPI hook_VirtualAllocEx(HANDLE proc, LPVOID addr, SIZE_T size,
                                         DWORD type, DWORD prot)
{
    DWORD err = GetLastError();
    LPVOID p;
    int obs = observing();
    p = real_VirtualAllocEx(proc, addr, size, type, prot);
    if (obs) {
        char ps[160], det[PW_DET_LEN];
        prot_str(prot, ps, sizeof(ps));
        fmt(det, sizeof(det), "在 PID %lu 的地址空间申请 %llu 字节（%s）",
            (unsigned long)GetProcessId(proc), (unsigned long long)size, ps);
        pw_report(PW_CAT_MEM, PW_LVL_SUSPECT, "VirtualAllocEx", "(目标进程)", det,
                  (unsigned)size, 0);
    }
    SetLastError(err);
    return p;
}

static BOOL WINAPI hook_VirtualProtectEx(HANDLE proc, LPVOID addr, SIZE_T size,
                                         DWORD prot, PDWORD old)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    DWORD was = 0;
    if (old) was = *old;
    ok = real_VirtualProtectEx(proc, addr, size, prot, old);
    if (obs && (prot_has_exec(prot) || prot_has_exec(was))) {
        char a[160], b[160], det[PW_DET_LEN];
        prot_str(was, a, sizeof(a));
        prot_str(prot, b, sizeof(b));
        fmt(det, sizeof(det), "PID %lu：%s -> %s，%llu 字节",
            (unsigned long)GetProcessId(proc), a, b, (unsigned long long)size);
        pw_report(PW_CAT_MEM, PW_LVL_SUSPECT, "VirtualProtectEx", "(目标进程)", det,
                  (unsigned)size, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

static BOOL WINAPI hook_WriteProcessMemory(HANDLE proc, LPVOID addr, LPCVOID buf,
                                           SIZE_T size, PSIZE_T written)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_WriteProcessMemory(proc, addr, buf, size, written);
    if (obs) {
        char det[PW_DET_LEN];
        fmt(det, sizeof(det), "向 PID %lu 的 0x%p 写入 %llu 字节",
            (unsigned long)GetProcessId(proc), addr, (unsigned long long)size);
        pw_report(PW_CAT_MEM, PW_LVL_SUSPECT, "WriteProcessMemory",
                  "(目标进程)", det, (unsigned)size, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

static HANDLE WINAPI hook_CreateRemoteThread(HANDLE proc, LPSECURITY_ATTRIBUTES sa,
                                             SIZE_T stack, LPTHREAD_START_ROUTINE start,
                                             LPVOID param, DWORD flags, LPDWORD tid)
{
    DWORD err = GetLastError();
    HANDLE h;
    int obs = observing();
    h = real_CreateRemoteThread(proc, sa, stack, start, param, flags, tid);
    if (obs) {
        char det[PW_DET_LEN];
        fmt(det, sizeof(det), "在 PID %lu 中创建线程，入口 0x%p，参数 0x%p",
            (unsigned long)GetProcessId(proc), (void *)start, param);
        pw_report(PW_CAT_MEM, PW_LVL_SUSPECT, "CreateRemoteThread",
                  "(目标进程)", det, 0, h ? 0 : -1);
    }
    SetLastError(err);
    return h;
}

static HANDLE WINAPI hook_OpenProcess(DWORD access, BOOL inherit, DWORD pid)
{
    DWORD err = GetLastError();
    HANDLE h;
    int obs = observing();
    h = real_OpenProcess(access, inherit, pid);
    if (obs && h &&
        (access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD))) {
        char det[PW_DET_LEN], acc[200];
        acc[0] = 0;
        if (access & PROCESS_VM_WRITE)      pw_str_cat(acc, sizeof(acc), "VM_WRITE ");
        if (access & PROCESS_VM_OPERATION)  pw_str_cat(acc, sizeof(acc), "VM_OPERATION ");
        if (access & PROCESS_VM_READ)       pw_str_cat(acc, sizeof(acc), "VM_READ ");
        if (access & PROCESS_CREATE_THREAD) pw_str_cat(acc, sizeof(acc), "CREATE_THREAD ");
        if (access & PROCESS_TERMINATE)     pw_str_cat(acc, sizeof(acc), "TERMINATE ");
        fmt(det, sizeof(det), "打开 PID %lu，权限 %s", (unsigned long)pid, acc);
        pw_report(PW_CAT_MEM, PW_LVL_SUSPECT, "OpenProcess", "(其它进程)", det, 0, 0);
    }
    SetLastError(err);
    return h;
}

static BOOL WINAPI hook_QueueUserAPC(PAPCFUNC fn, HANDLE thread, ULONG_PTR data)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = observing();
    ok = real_QueueUserAPC(fn, thread, data);
    if (obs) {
        char det[PW_DET_LEN];
        fmt(det, sizeof(det), "向线程插入 APC，回调 0x%p（早期注入常用手法）",
            (void *)fn);
        pw_report(PW_CAT_MEM, PW_LVL_SUSPECT, "QueueUserAPC", "(目标线程)", det, 0,
                  ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

/* ------------------------------------------------------------------ table */

#define H(n, f, r, g) { n, (void *)(f), (void **)(r), g, 0, 0, {0}, 0 }

PW_HOOK pw_hook_table[] = {
    /* file */
    H("CreateFileW",           hook_CreateFileW,           &real_CreateFileW,           "kernelbase"),
    H("CreateFileA",           hook_CreateFileA,           &real_CreateFileA,           "kernelbase"),
    H("ReadFile",              hook_ReadFile,              &real_ReadFile,              "kernelbase"),
    H("WriteFile",             hook_WriteFile,             &real_WriteFile,             "kernelbase"),
    H("DeleteFileW",           hook_DeleteFileW,           &real_DeleteFileW,           "kernelbase"),
    H("DeleteFileA",           hook_DeleteFileA,           &real_DeleteFileA,           "kernelbase"),
    H("MoveFileExW",           hook_MoveFileExW,           &real_MoveFileExW,           "kernelbase"),
    H("CopyFileW",             hook_CopyFileW,             &real_CopyFileW,             "kernelbase"),
    H("CreateDirectoryW",      hook_CreateDirectoryW,      &real_CreateDirectoryW,      "kernelbase"),
    H("RemoveDirectoryW",      hook_RemoveDirectoryW,      &real_RemoveDirectoryW,      "kernelbase"),
    H("FindFirstFileW",        hook_FindFirstFileW,        &real_FindFirstFileW,        "kernelbase"),
    H("FindFirstFileExW",      hook_FindFirstFileExW,      &real_FindFirstFileExW,      "kernelbase"),
    H("SetFileAttributesW",    hook_SetFileAttributesW,    &real_SetFileAttributesW,    "kernelbase"),
    H("CloseHandle",           hook_CloseHandle,           &real_CloseHandle,           "kernelbase"),
    /* registry */
    H("RegOpenKeyExW",         hook_RegOpenKeyExW,         &real_RegOpenKeyExW,         "advapi32"),
    H("RegCreateKeyExW",       hook_RegCreateKeyExW,       &real_RegCreateKeyExW,       "advapi32"),
    H("RegSetValueExW",        hook_RegSetValueExW,        &real_RegSetValueExW,        "advapi32"),
    H("RegQueryValueExW",      hook_RegQueryValueExW,      &real_RegQueryValueExW,      "advapi32"),
    H("RegDeleteValueW",       hook_RegDeleteValueW,       &real_RegDeleteValueW,       "advapi32"),
    H("RegDeleteKeyW",         hook_RegDeleteKeyW,         &real_RegDeleteKeyW,         "advapi32"),
    H("RegDeleteKeyExW",       hook_RegDeleteKeyExW,       &real_RegDeleteKeyExW,       "advapi32"),
    H("RegOpenKeyExA",         hook_RegOpenKeyExA,         &real_RegOpenKeyExA,         "advapi32"),
    H("RegCreateKeyExA",       hook_RegCreateKeyExA,       &real_RegCreateKeyExA,       "advapi32"),
    H("RegSetValueExA",        hook_RegSetValueExA,        &real_RegSetValueExA,        "advapi32"),
    H("RegQueryValueExA",      hook_RegQueryValueExA,      &real_RegQueryValueExA,      "advapi32"),
    H("RegDeleteValueA",       hook_RegDeleteValueA,       &real_RegDeleteValueA,       "advapi32"),
    H("RegDeleteKeyA",         hook_RegDeleteKeyA,         &real_RegDeleteKeyA,         "advapi32"),
    /* sockets */
    H("socket",                hook_socket,                &real_socket,                "ws2_32"),
    H("connect",               hook_connect,               &real_connect,               "ws2_32"),
    H("WSAConnect",            hook_WSAConnect,            &real_WSAConnect,            "ws2_32"),
    H("send",                  hook_send,                  &real_send,                  "ws2_32"),
    H("recv",                  hook_recv,                  &real_recv,                  "ws2_32"),
    H("WSASend",               hook_WSASend,               &real_WSASend,               "ws2_32"),
    H("WSARecv",               hook_WSARecv,               &real_WSARecv,               "ws2_32"),
    H("sendto",                hook_sendto,                &real_sendto,                "ws2_32"),
    H("recvfrom",              hook_recvfrom,              &real_recvfrom,              "ws2_32"),
    H("closesocket",           hook_closesocket,           &real_closesocket,           "ws2_32"),
    H("getaddrinfo",           hook_getaddrinfo,           &real_getaddrinfo,           "ws2_32"),
    H("GetAddrInfoW",          hook_GetAddrInfoW,          &real_GetAddrInfoW,          "ws2_32"),
    H("gethostbyname",         hook_gethostbyname,         &real_gethostbyname,         "ws2_32"),
    /* http */
    H("InternetOpenW",         hook_InternetOpenW,         &real_InternetOpenW,         "wininet"),
    H("InternetOpenA",         hook_InternetOpenA,         &real_InternetOpenA,         "wininet"),
    H("InternetConnectW",      hook_InternetConnectW,      &real_InternetConnectW,      "wininet"),
    H("InternetOpenUrlW",      hook_InternetOpenUrlW,      &real_InternetOpenUrlW,      "wininet"),
    H("HttpOpenRequestW",      hook_HttpOpenRequestW,      &real_HttpOpenRequestW,      "wininet"),
    H("HttpSendRequestW",      hook_HttpSendRequestW,      &real_HttpSendRequestW,      "wininet"),
    H("InternetReadFile",      hook_InternetReadFile,      &real_InternetReadFile,      "wininet"),
    H("InternetSetOptionW",    hook_InternetSetOptionW,    &real_InternetSetOptionW,    "wininet"),
    H("WinHttpOpen",           pw_hook_WinHttpOpen,        &pw_real_WinHttpOpen,        "winhttp"),
    H("WinHttpConnect",        pw_hook_WinHttpConnect,     &pw_real_WinHttpConnect,     "winhttp"),
    H("WinHttpOpenRequest",    pw_hook_WinHttpOpenRequest, &pw_real_WinHttpOpenRequest, "winhttp"),
    H("WinHttpSendRequest",    pw_hook_WinHttpSendRequest, &pw_real_WinHttpSendRequest, "winhttp"),
    H("WinHttpReceiveResponse",pw_hook_WinHttpReceiveResponse,
                                                       &pw_real_WinHttpReceiveResponse, "winhttp"),
    H("WinHttpSetOption",      pw_hook_WinHttpSetOption,   &pw_real_WinHttpSetOption,   "winhttp"),
    H("WinHttpGetProxyForUrl", pw_hook_WinHttpGetProxyForUrl,
                                                        &pw_real_WinHttpGetProxyForUrl, "winhttp"),
    H("WinHttpGetIEProxyConfigForCurrentUser",
                               pw_hook_WinHttpGetIEProxyConfigForCurrentUser,
                                         &pw_real_WinHttpGetIEProxyConfigForCurrentUser,
                                                                                        "winhttp"),
    /* process */
    H("CreateProcessW",        hook_CreateProcessW,        &real_CreateProcessW,        "kernelbase"),
    H("CreateProcessA",        hook_CreateProcessA,        &real_CreateProcessA,        "kernelbase"),
    H("WinExec",               hook_WinExec,               &real_WinExec,               "kernelbase"),
    H("ShellExecuteExW",       hook_ShellExecuteExW,       &real_ShellExecuteExW,       "shell32"),
    H("CreateProcessAsUserW",  hook_CreateProcessAsUserW,  &real_CreateProcessAsUserW,  "advapi32"),
    /* modules */
    H("LoadLibraryExW",        hook_LoadLibraryExW,        &real_LoadLibraryExW,        "kernelbase"),
    H("LoadLibraryW",          hook_LoadLibraryW,          &real_LoadLibraryW,          "kernelbase"),
    H("LoadLibraryA",          hook_LoadLibraryA,          &real_LoadLibraryA,          "kernelbase"),
    H("GetProcAddress",        hook_GetProcAddress,        &real_GetProcAddress,        "kernelbase"),
    /* memory */
    H("VirtualAlloc",          hook_VirtualAlloc,          &real_VirtualAlloc,          "kernelbase"),
    H("VirtualProtect",        hook_VirtualProtect,        &real_VirtualProtect,        "kernelbase"),
    H("VirtualAllocEx",        hook_VirtualAllocEx,        &real_VirtualAllocEx,        "kernelbase"),
    H("VirtualProtectEx",      hook_VirtualProtectEx,      &real_VirtualProtectEx,      "kernelbase"),
    H("WriteProcessMemory",    hook_WriteProcessMemory,    &real_WriteProcessMemory,    "kernelbase"),
    H("CreateRemoteThread",    hook_CreateRemoteThread,    &real_CreateRemoteThread,    "kernelbase"),
    H("OpenProcess",           hook_OpenProcess,           &real_OpenProcess,           "kernelbase"),
    H("QueueUserAPC",          hook_QueueUserAPC,          &real_QueueUserAPC,          "kernelbase"),
};

const int pw_hook_table_count =
    (int)(sizeof(pw_hook_table) / sizeof(pw_hook_table[0]));
