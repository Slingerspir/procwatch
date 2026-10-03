/* pw_http.c - a minimal HTTP/1.1 server serving the WebUI.
 *
 * Deliberately small: one accept loop, one thread per connection (capped), no
 * external libraries, and Server-Sent Events for the live stream so the browser
 * never has to poll. Everything the target does on the wire is reported through
 * the hooks; everything *this* server does runs on threads holding the
 * suppression flag, so its own sockets and file writes never appear in the log.
 *
 * Responses are streamed through a small flush buffer rather than assembled in
 * memory: an event can carry a 384 byte path and a 320 byte detail, and a few
 * thousand of those would otherwise need multi-megabyte scratch buffers. */
#include "pw_http.h"
#include "pw_state.h"
#include "pw_util.h"
#include "pw_hooks.h"
#include "pw_gui.h"
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pw_webui_html.h"
#include "pw_lang.h"

#define MAX_CLIENTS      48
#define REQ_MAX          16384
#define SSE_BATCH        150
#define SSE_BUF_SIZE     (SSE_BATCH * 1400 + 4096)
#define OUT_BUF_SIZE     16384

static SOCKET            g_listen = INVALID_SOCKET;
static int               g_port = 0;
static HANDLE            g_accept_thread = NULL;
static volatile long     g_running = 0;
static volatile long     g_clients = 0;
static volatile long     g_sse_clients = 0;
static int               g_wsa_ready = 0;

/* ------------------------------------------------------------ socket output */

typedef struct {
    SOCKET s;
    char   buf[OUT_BUF_SIZE];
    int    used;
    int    ok;          /* cleared once a send fails */
} PW_OUT;

static void out_init(PW_OUT *o, SOCKET s)
{
    o->s = s;
    o->used = 0;
    o->ok = 1;
}

static void out_flush(PW_OUT *o)
{
    int off = 0;
    if (!o->ok || o->used == 0) { o->used = 0; return; }
    while (off < o->used) {
        int n = send(o->s, o->buf + off, o->used - off, 0);
        if (n <= 0) { o->ok = 0; break; }
        off += n;
    }
    o->used = 0;
}

static void out_write(PW_OUT *o, const char *p, int n)
{
    if (!o->ok || n <= 0) return;
    if (n >= OUT_BUF_SIZE) {
        out_flush(o);
        if (!o->ok) return;
        {
            int off = 0;
            while (off < n) {
                int w = send(o->s, p + off, n - off, 0);
                if (w <= 0) { o->ok = 0; return; }
                off += w;
            }
        }
        return;
    }
    if (o->used + n > OUT_BUF_SIZE) out_flush(o);
    if (!o->ok) return;
    memcpy(o->buf + o->used, p, (size_t)n);
    o->used += n;
}

static void out_puts(PW_OUT *o, const char *str)
{
    out_write(o, str, (int)strlen(str));
}

/* Every string that reaches a JSON body goes through here. Windows paths are
 * full of backslashes, and "\U" is not a legal JSON escape - emitting a path
 * raw makes the whole response unparseable, which silently blanks out the
 * fields the page renders. */
static void out_json_str(PW_OUT *o, const char *s)
{
    char esc[2048];
    if (!s) { out_puts(o, "\"\""); return; }
    pw_json_escape(s, esc, sizeof(esc));
    out_puts(o, "\"");
    out_puts(o, esc);
    out_puts(o, "\"");
}

static void out_printf(PW_OUT *o, const char *f, ...)
{
    char tmp[2048];
    va_list ap;
    int n;
    va_start(ap, f);
    n = vsnprintf(tmp, sizeof(tmp), f, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof(tmp)) n = (int)sizeof(tmp) - 1;
    out_write(o, tmp, n);
}

/* ------------------------------------------------------------------ headers */

/* Buffered response: the caller knows the exact length. */
static void head_len(PW_OUT *o, int code, const char *ctype, long len, const char *extra)
{
    const char *reason = (code == 200) ? "OK" :
                         (code == 204) ? "No Content" :
                         (code == 404) ? "Not Found" :
                         (code == 503) ? "Service Unavailable" : "Bad Request";
    out_printf(o, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %ld\r\n"
                  "Cache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\n"
                  "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                  "Access-Control-Allow-Headers: *\r\n%sConnection: close\r\n\r\n",
               code, reason, ctype, len, extra ? extra : "");
}

/* Streamed response: no length, the body ends when the connection closes. */
static void head_stream(PW_OUT *o, int code, const char *ctype, const char *extra)
{
    const char *reason = (code == 200) ? "OK" : "OK";
    out_printf(o, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                  "Cache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\n"
                  "%sConnection: close\r\n\r\n",
               code, reason, ctype, extra ? extra : "");
}

static void reply_text(PW_OUT *o, int code, const char *ctype, const char *body)
{
    head_len(o, code, ctype, (long)strlen(body), NULL);
    out_puts(o, body);
    out_flush(o);
}

/* ------------------------------------------------------------------- routes */

static long qs_int(const char *query, const char *key, long def)
{
    const char *p = query;
    size_t klen = strlen(key);
    if (!p) return def;
    while (*p) {
        if (!_strnicmp(p, key, klen) && p[klen] == '=') return atol(p + klen + 1);
        p = strchr(p, '&');
        if (!p) break;
        p++;
    }
    return def;
}

static void reply_meta(PW_OUT *o)
{
    unsigned long long now = pw_now_ms();
    unsigned int counts[9], lvls[4];
    unsigned long long total = 0;
    char cfg[512];

    pw_log_stats(&g_log, &total, counts, 9, lvls, 4);
    pw_config_to_string(&g_cfg, cfg, sizeof(cfg));

    out_puts(o, "{\"product\":\"" PW_PRODUCT "\",\"version\":\"" PW_VERSION "\",");
    out_printf(o, "\"pid\":%lu,\"exe\":", (unsigned long)g_pid);
    out_json_str(o, g_exe_name);
    out_puts(o, ",\"path\":");
    out_json_str(o, g_exe_path);
    out_puts(o, ",\"user\":");
    out_json_str(o, g_user);
    out_printf(o, ",\"arch\":\"%s\",\"url\":\"%s\",\"lang\":\"%s\",",
#ifdef _WIN64
               "x64",
#else
               "x86",
#endif
               g_http_url, pw_lang_is_en() ? "en" : "zh");
    out_printf(o, "\"startedMs\":%llu,\"uptimeMs\":%llu,\"events\":%llu,\"cached\":%u,",
               g_start_ms, now - g_start_ms, total, (unsigned)pw_log_count(&g_log));
    out_printf(o, "\"suspect\":%u,\"warn\":%u,\"dropped\":%lld,"
                  "\"hooks\":%d,\"patches\":%d,\"redirects\":%d,"
                  "\"gui\":%d,\"http\":%d,\"port\":%d,"
                  "\"active\":%ld,\"paused\":%ld,\"clients\":%ld,\"config\":",
               lvls[PW_LVL_SUSPECT], lvls[PW_LVL_WARN], g_pw_dropped,
               pw_hooks_installed_count(), pw_hooks_patch_site_count(),
               pw_hooks_redirect_count(),
               pw_gui_running(), g_cfg.http, g_port, g_active, g_paused, g_clients);
    out_json_str(o, cfg);
    out_puts(o, "}");
}

static void reply_stats(PW_OUT *o)
{
    static const char *const CN[9] = { "", "file", "reg", "net", "http",
                                       "proc", "mod", "mem", "sys" };
    unsigned int counts[9], lvls[4];
    unsigned long long total = 0;
    int i;

    pw_log_stats(&g_log, &total, counts, 9, lvls, 4);
    out_printf(o, "{\"total\":%llu,\"cached\":%u,\"dropped\":%lld,\"cat\":{",
               total, (unsigned)pw_log_count(&g_log), g_pw_dropped);
    for (i = 1; i <= 8; i++)
        out_printf(o, "%s\"%s\":%u", i > 1 ? "," : "", CN[i], counts[i]);
    out_printf(o, "},\"lvl\":{\"info\":%u,\"warn\":%u,\"suspect\":%u}}",
               lvls[0], lvls[1], lvls[2]);
}

static void reply_hooks(PW_OUT *o)
{
    int i;
    out_puts(o, "{\"hooks\":[");
    for (i = 0; i < pw_hook_table_count; i++) {
        PW_HOOK *h = &pw_hook_table[i];
        out_printf(o, "%s{\"name\":\"%s\",\"group\":\"%s\",\"resolved\":%d,"
                      "\"redirects\":%d,\"iatHits\":%d}",
                   i ? "," : "", h->name, h->group, *h->orig ? 1 : 0,
                   h->redirects, h->iat_hits);
    }
    out_printf(o, "],\"count\":%d,\"patches\":%d,\"redirects\":%d}",
               pw_hook_table_count, pw_hooks_patch_site_count(),
               pw_hooks_redirect_count());
}

static void reply_modules(PW_OUT *o)
{
    HANDLE snap;
    MODULEENTRY32W me;
    int first = 1;

    out_puts(o, "{\"modules\":[");
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_pid);
    if (snap != INVALID_HANDLE_VALUE) {
        memset(&me, 0, sizeof(me));
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                char name8[300], path8[900];
                pw_wide_to_utf8(me.szModule, name8, sizeof(name8));
                pw_wide_to_utf8(me.szExePath, path8, sizeof(path8));
                out_printf(o, "%s{\"name\":", first ? "" : ",");
                out_json_str(o, name8);
                out_puts(o, ",\"path\":");
                out_json_str(o, path8);
                out_printf(o, ",\"base\":\"%p\",\"size\":%u}",
                           (void *)me.modBaseAddr, (unsigned)me.modBaseSize);
                first = 0;
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    out_puts(o, "]}");
}

/* Stream every event newer than `after`, up to `limit`. */
static void reply_events(PW_OUT *o, const char *query)
{
    unsigned long long after = (unsigned long long)qs_int(query, "after", 0);
    long limit = qs_int(query, "limit", 500);
    PW_EVENT *evs;
    unsigned long long last = 0;
    long sent = 0;

    if (limit <= 0) limit = 500;
    if (limit > 20000) limit = 20000;

    evs = (PW_EVENT *)malloc(sizeof(PW_EVENT) * 128);
    if (!evs) { reply_text(o, 503, "text/plain", "oom"); return; }

    head_stream(o, 200, "application/json; charset=utf-8", NULL);
    out_puts(o, "{\"events\":[");
    for (;;) {
        unsigned int n, i;
        n = pw_log_since(&g_log, after, evs, 128, &last);
        if (n == 0) break;
        for (i = 0; i < n; i++) {
            char line[2048];
            int w;
            if (sent >= limit) break;
            w = pw_event_json(&evs[i], (unsigned long)g_pid, line, sizeof(line));
            if (w < 0) continue;              /* pathologically long: skip */
            if (sent) out_puts(o, ",");
            out_write(o, line, w);
            sent++;
        }
        after = evs[n - 1].seq;
        if (sent >= limit || n < 128) break;
        if (!o->ok) break;
    }
    out_printf(o, "],\"last\":%llu,\"returned\":%ld}", last, sent);
    out_flush(o);
    free(evs);
}

static void reply_export(PW_OUT *o, const char *query)
{
    int csv = (query && strstr(query, "csv")) ? 1 : 0;
    PW_EVENT *evs = (PW_EVENT *)malloc(sizeof(PW_EVENT) * 256);
    unsigned long long cursor = 0, last = 0;
    char extra[256];

    if (!evs) { reply_text(o, 503, "text/plain", "oom"); return; }

    _snprintf(extra, sizeof(extra),
              "Content-Disposition: attachment; filename=\"procwatch-%lu.%s\"\r\n",
              (unsigned long)g_pid, csv ? "csv" : "jsonl");
    extra[sizeof(extra) - 1] = 0;
    head_stream(o, 200, csv ? "text/csv; charset=utf-8"
                            : "application/x-ndjson; charset=utf-8", extra);
    if (csv) {
        out_puts(o, "\xEF\xBB\xBF");
        out_puts(o, "\"time\",\"pid\",\"tid\",\"category\",\"level\",\"api\",\"target\",\"detail\"\n");
    }

    for (;;) {
        unsigned int n, i;
        n = pw_log_since(&g_log, cursor, evs, 256, &last);
        if (n == 0) break;
        for (i = 0; i < n; i++) {
            const PW_EVENT *e = &evs[i];
            if (csv) {
                char ts[40], f0[80], f1[64], f2[64], f3[200], f4[1600], f5[1400];
                pw_iso_str(e->ts, ts, sizeof(ts));
                pw_csv_field(ts, f0, sizeof(f0));
                pw_csv_field(pw_cat_name(e->cat), f1, sizeof(f1));
                pw_csv_field(pw_lvl_name(e->lvl), f2, sizeof(f2));
                pw_csv_field(e->api, f3, sizeof(f3));
                pw_csv_field(e->target, f4, sizeof(f4));
                pw_csv_field(e->detail, f5, sizeof(f5));
                out_printf(o, "%s,%lu,%u,%s,%s,%s,%s,%s\r\n", f0,
                           (unsigned long)g_pid, e->tid, f1, f2, f3, f4, f5);
            } else {
                char line[2048];
                int w = pw_event_json(e, (unsigned long)g_pid, line, sizeof(line));
                if (w > 0) {
                    out_write(o, line, w);
                    out_write(o, "\n", 1);
                }
            }
        }
        cursor = evs[n - 1].seq;
        if (n < 256 || cursor >= last || !o->ok) break;
    }
    out_flush(o);
    free(evs);
}

/* Server-Sent Events: the page subscribes once and receives each new event as
 * it happens. A comment line every 15s keeps intermediaries from timing the
 * connection out during quiet periods. */
static void serve_sse(SOCKET s, unsigned long long startAfter)
{
    char *buf;
    PW_EVENT *evs;
    unsigned long long cursor = startAfter;
    unsigned long long lastPing = pw_now_ms();

    if (InterlockedIncrement(&g_sse_clients) > 6) {
        InterlockedDecrement(&g_sse_clients);
        {
            PW_OUT o;
            out_init(&o, s);
            reply_text(&o, 503, "text/plain", "too many streams");
        }
        return;
    }

    buf = (char *)malloc(SSE_BUF_SIZE);
    evs = (PW_EVENT *)malloc(sizeof(PW_EVENT) * SSE_BATCH);
    if (!buf || !evs) {
        free(buf); free(evs);
        InterlockedDecrement(&g_sse_clients);
        return;
    }

    {
        PW_OUT o;
        char hello[160];
        out_init(&o, s);
        out_puts(&o, "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/event-stream; charset=utf-8\r\n"
                     "Cache-Control: no-cache, no-transform\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "Connection: keep-alive\r\n\r\n");
        _snprintf(hello, sizeof(hello), "retry: 2000\n: connected cursor=%llu\n\n", cursor);
        hello[sizeof(hello) - 1] = 0;
        out_puts(&o, hello);
        out_flush(&o);
        if (!o.ok) {
            free(buf); free(evs);
            InterlockedDecrement(&g_sse_clients);
            return;
        }
    }

    while (g_running) {
        unsigned int n, i;
        unsigned long long last = 0;
        int cap = 0;

        n = pw_log_since(&g_log, cursor, evs, SSE_BATCH, &last);
        if (n) {
            cap = snprintf(buf, 64, "event: events\ndata: [");
            for (i = 0; i < n; i++) {
                int w = pw_event_json(&evs[i], (unsigned long)g_pid, buf + cap,
                                      SSE_BUF_SIZE - cap - 64);
                if (w < 0) break;
                cap += w;
                if (i + 1 < n) buf[cap++] = ',';
            }
            cap += snprintf(buf + cap, 32, "]\n\n");
            if (send(s, buf, cap, 0) <= 0) break;
            cursor = evs[n - 1].seq;
        } else if (last < cursor) {
            cursor = last;                       /* ring was cleared under us */
            if (send(s, "event: cleared\ndata: {}\n\n", 25, 0) <= 0) break;
        }

        if (pw_now_ms() - lastPing > 15000) {
            if (send(s, ": ping\n\n", 8, 0) <= 0) break;
            lastPing = pw_now_ms();
        }
        Sleep(300);
    }

    free(buf);
    free(evs);
    InterlockedDecrement(&g_sse_clients);
}

/* -------------------------------------------------------------- dispatching */

static void handle_request(PW_OUT *o, SOCKET raw, const char *method,
                           const char *path, const char *query)
{
    if (!strcmp(method, "OPTIONS")) {
        head_len(o, 204, "text/plain", 0, NULL);
        out_flush(o);
        return;
    }

    if (!strcmp(path, "/") || !strcmp(path, "/index.html")) {
        head_len(o, 200, "text/html; charset=utf-8", (long)pw_webui_html_len, NULL);
        out_write(o, (const char *)pw_webui_html, (int)pw_webui_html_len);
        out_flush(o);
        return;
    }

    if (!strcmp(path, "/api/meta"))    { head_stream(o, 200, "application/json; charset=utf-8", NULL); reply_meta(o); out_flush(o); return; }
    if (!strcmp(path, "/api/events"))  { reply_events(o, query); return; }
    if (!strcmp(path, "/api/stats"))   { head_stream(o, 200, "application/json; charset=utf-8", NULL); reply_stats(o); out_flush(o); return; }
    if (!strcmp(path, "/api/hooks"))   { head_stream(o, 200, "application/json; charset=utf-8", NULL); reply_hooks(o); out_flush(o); return; }
    if (!strcmp(path, "/api/modules")) { head_stream(o, 200, "application/json; charset=utf-8", NULL); reply_modules(o); out_flush(o); return; }
    if (!strcmp(path, "/api/export"))  { reply_export(o, query); return; }
    if (!strcmp(path, "/api/ping"))    { reply_text(o, 200, "text/plain", "pong"); return; }

    if (!strcmp(path, "/api/stream")) {
        out_flush(o);
        {
            unsigned long long after = (unsigned long long)qs_int(query, "after", 0);
            if (after == 0) after = pw_log_last_seq(&g_log);
            serve_sse(raw, after);
        }
        return;
    }

    if (!strcmp(path, "/api/clear")) {
        pw_log_clear(&g_log);
        pw_gui_refresh();
        reply_text(o, 200, "application/json", "{\"ok\":true}");
        return;
    }

    if (!strcmp(path, "/api/pause")) {
        long on = qs_int(query, "on", -1);
        char r[64];
        if (on == 0) g_paused = 0;
        else if (on == 1) g_paused = 1;
        else g_paused = !g_paused;
        _snprintf(r, sizeof(r), "{\"paused\":%ld}", g_paused);
        r[sizeof(r) - 1] = 0;
        reply_text(o, 200, "application/json", r);
        return;
    }

    if (!strcmp(path, "/api/config")) {
        long v;
        char r[256];
        if ((v = qs_int(query, "previews", -1)) >= 0) g_cfg.previews = (int)v;
        if ((v = qs_int(query, "verbose", -1)) >= 0)  g_cfg.verbose  = (int)v;
        if ((v = qs_int(query, "risk", -1)) >= 0)     g_cfg.risk     = (int)v;
        _snprintf(r, sizeof(r), "{\"previews\":%d,\"verbose\":%d,\"risk\":%d}",
                  g_cfg.previews, g_cfg.verbose, g_cfg.risk);
        r[sizeof(r) - 1] = 0;
        reply_text(o, 200, "application/json", r);
        return;
    }

    if (!strcmp(path, "/api/deactivate")) {
        char r[160];
        _snprintf(r, sizeof(r), "{\"ok\":true,\"restored\":%d}",
                  pw_hooks_patch_site_count());
        r[sizeof(r) - 1] = 0;
        reply_text(o, 200, "application/json", r);
        out_flush(o);
        Sleep(200);                       /* let the answer drain first */
        pw_report_force(PW_CAT_SYS, PW_LVL_WARN, "Deactivate", g_exe_name,
                        L("收到停用请求，已还原全部导入/导出表补丁"), 0, 0);
        pw_hooks_remove();
        g_paused = 1;
        g_active = 0;
        return;
    }

    reply_text(o, 404, "text/plain; charset=utf-8", "not found");
}

static DWORD WINAPI client_thread(LPVOID param)
{
    SOCKET s = (SOCKET)(ULONG_PTR)param;
    char *req = (char *)malloc(REQ_MAX);
    int got = 0, i;
    char method[16] = {0}, target[1024] = {0}, path[1024] = {0}, query[768] = {0};
    DWORD timeout = 3000, nodelay = 1;
    PW_OUT o;

    pw_suppress_enter();
    out_init(&o, s);

    if (!req) { closesocket(s); InterlockedDecrement(&g_clients); return 0; }

    while (got < REQ_MAX - 1) {
        int n = recv(s, req + got, REQ_MAX - 1 - got, 0);
        if (n <= 0) break;
        got += n;
        req[got] = 0;
        if (strstr(req, "\r\n\r\n")) break;
    }
    if (got <= 0) {
        free(req);
        closesocket(s);
        InterlockedDecrement(&g_clients);
        return 0;
    }
    req[got] = 0;

    /* Request line: METHOD SP target SP version */
    {
        char *sp1 = strchr(req, ' ');
        if (sp1) {
            char *sp2;
            size_t mlen = (size_t)(sp1 - req);
            if (mlen >= sizeof(method)) mlen = sizeof(method) - 1;
            memcpy(method, req, mlen);
            method[mlen] = 0;
            sp2 = strchr(sp1 + 1, ' ');
            if (sp2) {
                size_t tlen = (size_t)(sp2 - sp1 - 1);
                if (tlen >= sizeof(target)) tlen = sizeof(target) - 1;
                memcpy(target, sp1 + 1, tlen);
                target[tlen] = 0;
            }
        }
    }
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
    /* Absolute-form request target (when something proxies us). */
    {
        char *scheme = strstr(path, "://");
        if (scheme) {
            char *slash = strchr(scheme + 3, '/');
            if (slash) memmove(path, slash, strlen(slash) + 1);
            else pw_str_copy(path, sizeof(path), "/");
        }
    }

    /* Percent-decode the query so UTF-8 filter terms survive. */
    for (i = 0; query[i]; i++) {
        if (query[i] == '+') query[i] = ' ';
        else if (query[i] == '%' && query[i + 1] && query[i + 2]) {
            char hex[3];
            hex[0] = query[i + 1];
            hex[1] = query[i + 2];
            hex[2] = 0;
            query[i] = (char)strtol(hex, NULL, 16);
            memmove(query + i + 1, query + i + 3, strlen(query + i + 3) + 1);
        }
    }

    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

    handle_request(&o, s, method, path, query);
    out_flush(&o);

    free(req);
    closesocket(s);
    InterlockedDecrement(&g_clients);
    return 0;
}

static DWORD WINAPI accept_thread(LPVOID param)
{
    (void)param;
    pw_suppress_enter();

    while (g_running) {
        struct sockaddr_in from;
        int fromLen = sizeof(from);
        SOCKET c = accept(g_listen, (struct sockaddr *)&from, &fromLen);

        if (c == INVALID_SOCKET) {
            if (!g_running) break;
            Sleep(50);
            continue;
        }
        /* Loopback only: this is a debugging surface, not a network service. */
        if (from.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            closesocket(c);
            continue;
        }
        if (InterlockedIncrement(&g_clients) > MAX_CLIENTS) {
            InterlockedDecrement(&g_clients);
            closesocket(c);
            continue;
        }
        {
            HANDLE t = CreateThread(NULL, 0, client_thread, (LPVOID)(ULONG_PTR)c, 0, NULL);
            if (t) CloseHandle(t);
            else {
                closesocket(c);
                InterlockedDecrement(&g_clients);
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------- public */

int pw_http_port(void) { return g_port; }

int pw_http_start(void)
{
    WSADATA wsa;
    struct sockaddr_in addr;
    int port, tries;

    if (g_running) return g_port;

    if (!g_wsa_ready) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
        g_wsa_ready = 1;
    }

    for (tries = 0; tries < 200; tries++) {
        BOOL exclusive = TRUE;
        port = (g_cfg.port > 0 && tries == 0) ? g_cfg.port : (PW_PORT_BASE + tries);

        g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_listen == INVALID_SOCKET) return 0;

        setsockopt(g_listen, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   (const char *)&exclusive, sizeof(exclusive));

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((u_short)port);

        if (bind(g_listen, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
            listen(g_listen, 32) == 0) {
            g_port = port;
            break;
        }
        closesocket(g_listen);
        g_listen = INVALID_SOCKET;
    }

    if (g_listen == INVALID_SOCKET) {
        pw_report_force(PW_CAT_SYS, PW_LVL_WARN, "HttpStart", g_exe_name,
                        L("无法绑定任何端口，WebUI 未启动"), 0, 0);
        return 0;
    }

    g_running = 1;
    {
        char u[64];
        _snprintf(u, sizeof(u), "127.0.0.1:%d", g_port);
        u[sizeof(u) - 1] = 0;
        pw_str_copy(g_http_url, sizeof(g_http_url), u);
    }

    g_accept_thread = CreateThread(NULL, 0, accept_thread, NULL, 0, NULL);
    if (!g_accept_thread) {
        g_running = 0;
        closesocket(g_listen);
        g_listen = INVALID_SOCKET;
        return 0;
    }

    {
        char detail[256];
        _snprintf(detail, sizeof(detail),
                  L("WebUI 已启动：http://%s/  （仅监听 127.0.0.1）"), g_http_url);
        detail[sizeof(detail) - 1] = 0;
        pw_report_force(PW_CAT_SYS, PW_LVL_INFO, "HttpStart", g_exe_name, detail, 0, 0);
    }
    return g_port;
}

void pw_http_stop(void)
{
    if (!g_running) return;
    g_running = 0;
    if (g_listen != INVALID_SOCKET) {
        closesocket(g_listen);
        g_listen = INVALID_SOCKET;
    }
    if (g_accept_thread) {
        WaitForSingleObject(g_accept_thread, 1000);
        CloseHandle(g_accept_thread);
        g_accept_thread = NULL;
    }
}

/* Written with the suppression flag held, so recording our own bookkeeping file
 * does not show up as activity of the monitored process. */
void pw_http_write_discovery(void)
{
    char dir[MAX_PATH], path[MAX_PATH];
    FILE *f;

    pw_data_dir(dir, sizeof(dir));
    CreateDirectoryA(dir, NULL);
    _snprintf(path, sizeof(path), "%s\\%lu.json", dir, (unsigned long)g_pid);
    path[sizeof(path) - 1] = 0;

    f = fopen(path, "wb");
    if (!f) return;
    fprintf(f,
            "{\"pid\":%lu,\"exe\":\"%s\",\"path\":\"%s\",\"port\":%d,"
            "\"user\":\"%s\",\"startedMs\":%llu,\"version\":\"%s\","
            "\"gui\":%d,\"url\":\"http://%s/\"}\n",
            (unsigned long)g_pid, g_exe_name, g_exe_path, g_port,
            g_user, g_start_ms, PW_VERSION, pw_gui_running(), g_http_url);
    fclose(f);
}
