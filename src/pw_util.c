/* pw_util.c - helper implementations. No hooked API is used here, so this file
 * is safe to call from inside a hook. */
#include "pw_util.h"
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

unsigned long long pw_now_ms(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    /* 100ns ticks since 1601 -> ms since 1970 */
    return (u.QuadPart - 116444736000000000ULL) / 10000ULL;
}

void pw_ts_str(unsigned long long unix_ms, char *out, int outsz)
{
    ULARGE_INTEGER u;
    FILETIME ft;
    SYSTEMTIME st;
    u.QuadPart = unix_ms * 10000ULL + 116444736000000000ULL;
    ft.dwLowDateTime  = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    if (!FileTimeToLocalFileTime(&ft, &ft) || !FileTimeToSystemTime(&ft, &st)) {
        _snprintf(out, outsz, "--:--:--");
        out[outsz - 1] = 0;
        return;
    }
    _snprintf(out, outsz, "%02u:%02u:%02u.%03u",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    out[outsz - 1] = 0;
}

void pw_iso_str(unsigned long long unix_ms, char *out, int outsz)
{
    ULARGE_INTEGER u;
    FILETIME ft;
    SYSTEMTIME st;
    u.QuadPart = unix_ms * 10000ULL + 116444736000000000ULL;
    ft.dwLowDateTime  = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    if (!FileTimeToLocalFileTime(&ft, &ft) || !FileTimeToSystemTime(&ft, &st)) {
        pw_str_copy(out, outsz, "");
        return;
    }
    _snprintf(out, outsz, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
              st.wMilliseconds);
    out[outsz - 1] = 0;
}

int pw_streq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

int pw_streqi(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

int pw_ends_with_i(const char *s, const char *suffix)
{
    size_t ls, lf;
    if (!s || !suffix) return 0;
    ls = strlen(s);
    lf = strlen(suffix);
    if (lf > ls) return 0;
    return pw_streqi(s + (ls - lf), suffix);
}

int pw_contains_i(const char *hay, const char *needle)
{
    size_t ln;
    if (!hay || !needle) return 0;
    ln = strlen(needle);
    if (!ln) return 1;
    for (; *hay; hay++) {
        size_t i;
        for (i = 0; i < ln; i++) {
            char a = hay[i], b = needle[i];
            if (!a) return 0;
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
        }
        if (i == ln) return 1;
    }
    return 0;
}

const char *pw_base_name(const char *path)
{
    const char *p, *last = path;
    if (!path) return "";
    for (p = path; *p; p++)
        if (*p == '\\' || *p == '/') last = p + 1;
    return last;
}

void pw_str_copy(char *dst, int dstsz, const char *src)
{
    if (!dst || dstsz <= 0) return;
    if (!src) { dst[0] = 0; return; }
    strncpy(dst, src, (size_t)dstsz - 1);
    dst[dstsz - 1] = 0;
}

void pw_str_cat(char *dst, int dstsz, const char *src)
{
    size_t used;
    if (!dst || dstsz <= 0 || !src) return;
    used = strlen(dst);
    if (used >= (size_t)dstsz - 1) return;
    strncpy(dst + used, src, (size_t)dstsz - used - 1);
    dst[dstsz - 1] = 0;
}

void pw_wide_to_utf8(const wchar_t *w, char *out, int outsz)
{
    int n;
    if (!out || outsz <= 0) return;
    out[0] = 0;
    if (!w) return;
    n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outsz - 1, NULL, NULL);
    if (n <= 0) out[0] = 0;
    else out[n] = 0;
}

void pw_utf8_to_wide(const char *s, wchar_t *out, int outsz)
{
    int n;
    if (!out || outsz <= 0) return;
    out[0] = 0;
    if (!s) return;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, out, outsz - 1);
    if (n <= 0) out[0] = 0;
    else out[n] = 0;
}

void pw_ansi_to_utf8(const char *s, char *out, int outsz)
{
    wchar_t w[1024];
    int n;

    if (!out || outsz <= 0) return;
    out[0] = 0;
    if (!s) return;
    n = MultiByteToWideChar(CP_ACP, 0, s, -1, w, 1024);
    if (n <= 0) {
        /* Not valid in the system code page: fall back to the raw bytes so the
         * operator still sees something. */
        pw_str_copy(out, outsz, s);
        return;
    }
    pw_wide_to_utf8(w, out, outsz);
}

int pw_is_printable(const unsigned char *p, int n)
{
    int i, good = 0;
    for (i = 0; i < n; i++) {
        unsigned char c = p[i];
        if ((c >= 0x20 && c < 0x7F) || c == '\t' || c == '\r' || c == '\n')
            good++;
    }
    return n > 0 && (good * 100 / n) >= 85;
}

void pw_hex_ascii(const unsigned char *p, int n, char *out, int outsz)
{
    int i, pos = 0;
    if (outsz <= 0) return;
    out[0] = 0;
    for (i = 0; i < n && pos + 4 < outsz; i++)
        pos += _snprintf(out + pos, outsz - pos, "%02X ", p[i]);
    if (pos + 2 < outsz) {
        pos += _snprintf(out + pos, outsz - pos, " |");
        for (i = 0; i < n && pos + 2 < outsz; i++) {
            unsigned char c = p[i];
            out[pos++] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
        }
        out[pos++] = '|';
        out[pos] = 0;
    }
}

void pw_json_escape(const char *in, char *out, int outsz)
{
    int pos = 0;
    const unsigned char *p = (const unsigned char *)(in ? in : "");
    if (outsz <= 0) return;
    for (; *p && pos + 7 < outsz; p++) {
        unsigned char c = *p;
        switch (c) {
        case '"':  out[pos++] = '\\'; out[pos++] = '"';  break;
        case '\\': out[pos++] = '\\'; out[pos++] = '\\'; break;
        case '\n': out[pos++] = '\\'; out[pos++] = 'n';  break;
        case '\r': out[pos++] = '\\'; out[pos++] = 'r';  break;
        case '\t': out[pos++] = '\\'; out[pos++] = 't';  break;
        default:
            if (c < 0x20) pos += _snprintf(out + pos, outsz - pos, "\\u%04X", c);
            else out[pos++] = (char)c;
        }
    }
    out[pos] = 0;
}

void pw_csv_field(const char *in, char *out, int outsz)
{
    int pos = 0;
    const char *p = in ? in : "";
    if (outsz < 3) { if (outsz > 0) out[0] = 0; return; }
    out[pos++] = '"';
    for (; *p && pos + 3 < outsz; p++) {
        if (*p == '"') out[pos++] = '"';
        out[pos++] = *p;
    }
    out[pos++] = '"';
    out[pos] = 0;
}

void pw_format_sockaddr(const struct sockaddr *sa, int salen, char *out, int outsz)
{
    (void)salen;
    if (outsz <= 0) return;
    out[0] = 0;
    if (!sa) { pw_str_copy(out, outsz, "?"); return; }
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)sa;
        unsigned int ip = (unsigned int)ntohl(v4->sin_addr.s_addr);
        _snprintf(out, outsz, "%u.%u.%u.%u:%u",
                  (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                  (unsigned)ntohs(v4->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)sa;
        int i;
        char *w = out;
        int left = outsz;
        for (i = 0; i < 16; i += 2) {
            int n = _snprintf(w, left, "%s%02x%02x",
                              i ? ":" : "",
                              v6->sin6_addr.s6_addr[i],
                              v6->sin6_addr.s6_addr[i + 1]);
            if (n <= 0 || n >= left) break;
            w += n; left -= n;
        }
        _snprintf(w, left > 0 ? left : 0, ":%u", (unsigned)ntohs(v6->sin6_port));
    } else if (sa->sa_family == AF_UNIX) {
        pw_str_copy(out, outsz, "(unix socket)");
    } else {
        _snprintf(out, outsz, "(af=%d)", sa->sa_family);
    }
    out[outsz - 1] = 0;
}

int pw_sockaddr_is_local(const struct sockaddr *sa)
{
    if (!sa) return 1;
    if (sa->sa_family == AF_INET) {
        unsigned long ip = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
        if ((ip >> 24) == 127) return 1;
        if ((ip >> 24) == 10) return 1;
        if ((ip >> 20) == (172 << 4 | 1)) return 1;   /* 172.16/12 */
        if ((ip >> 16) == (192 << 8 | 168)) return 1; /* 192.168/16 */
        if ((ip >> 24) == 0 || ip == 0xFFFFFFFFUL) return 1;
        return 0;
    }
    if (sa->sa_family == AF_INET6) {
        const unsigned char *b = ((const struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
        static const unsigned char loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        static const unsigned char any[16] = {0};
        if (memcmp(b, loop, 16) == 0 || memcmp(b, any, 16) == 0) return 1;
        if ((b[0] & 0xFE) == 0xFC) return 1;   /* fc00::/7 */
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return 1; /* fe80::/10 */
        return 0;
    }
    return 1;
}

void pw_path_join(char *out, int outsz, const char *a, const char *b)
{
    size_t la;
    pw_str_copy(out, outsz, a);
    la = strlen(out);
    if (la && out[la - 1] != '\\' && out[la - 1] != '/')
        pw_str_cat(out, outsz, "\\");
    pw_str_cat(out, outsz, b);
}

void pw_dir_create_for_file(const char *file)
{
    char dir[MAX_PATH * 2];
    char *p;
    pw_str_copy(dir, sizeof(dir), file);
    p = strrchr(dir, '\\');
    if (!p) return;
    *p = 0;
    /* Create the full chain, one level at a time. */
    for (p = dir; *p; p++) {
        if (*p == '\\' && p != dir) {
            *p = 0;
            CreateDirectoryA(dir, NULL);
            *p = '\\';
        }
    }
    CreateDirectoryA(dir, NULL);
}

void pw_get_temp_dir(char *out, int outsz)
{
    DWORD n = GetTempPathA((DWORD)outsz, out);
    if (n == 0 || n >= (DWORD)outsz) pw_str_copy(out, outsz, "C:\\Windows\\Temp\\");
    out[outsz - 1] = 0;
}

void pw_data_dir(char *out, int outsz)
{
    char tmp[MAX_PATH];
    pw_get_temp_dir(tmp, sizeof(tmp));
    pw_path_join(out, outsz, tmp, PW_DIR_NAME);
}

int pw_path_matches_any(const char *path, const char *const *pats, int npat)
{
    int i;
    if (!path) return 0;
    for (i = 0; i < npat; i++)
        if (pw_contains_i(path, pats[i])) return 1;
    return 0;
}
