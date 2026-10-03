/* pw_hookutil.h - helpers shared by the hook translation units.
 *
 * These are static inline on purpose: MinGW's winhttp.h and wininet.h declare
 * conflicting types and cannot be included from the same file, so the HTTP
 * hooks are split in two. Both copies of a helper compile away identically. */
#ifndef PW_HOOKUTIL_H
#define PW_HOOKUTIL_H

#include "pw_state.h"
#include "pw_util.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Are we currently in a position to record anything at all? Checked before any
 * expensive work (path resolution, previews). */
static inline int pw_observing(void)
{
    return g_active && !g_paused && !pw_suppressed();
}

static inline void pw_fmt(char *buf, int n, const char *f, ...)
{
    va_list ap;
    if (n <= 0) return;
    va_start(ap, f);
    vsnprintf(buf, (size_t)n, f, ap);
    va_end(ap);
    buf[n - 1] = 0;
}

/* Payload preview: text when the bytes look like text, hex otherwise. Only
 * consulted when the operator enabled previews, since this copies data the
 * monitored process controls into the event ring. */
static inline void pw_preview(const void *data, unsigned int len, char *out, int outsz)
{
    const unsigned char *p = (const unsigned char *)data;
    unsigned int take;

    out[0] = 0;
    if (!g_cfg.previews || !p || len == 0) return;

    take = len > 128 ? 128 : len;
    if (pw_is_printable(p, (int)take)) {
        unsigned int i;
        int pos = snprintf(out, (size_t)outsz, "预览[%u]: ", len);
        for (i = 0; i < take && pos < outsz - 1; i++) {
            unsigned char c = p[i];
            out[pos++] = (c == '\r' || c == '\n' || c == '\t') ? ' ' :
                         (c >= 0x20 && c < 0x7F) ? (char)c : '.';
        }
        out[pos] = 0;
    } else {
        char hex[420];
        pw_hex_ascii(p, (int)(take > 48 ? 48 : take), hex, sizeof(hex));
        pw_fmt(out, outsz, "预览[%u]: %s", len, hex);
    }
}

/* WinINet and WinHTTP both hand over header blocks as CRLF separated text.
 * Keep the fields an analyst actually reads. */
static inline void pw_summarise_headers(const char *headers, char *out, int outsz)
{
    static const char *const WANT[] = {
        "host:", "user-agent:", "content-type:", "content-length:",
        "authorization:", "cookie:", "referer:", "x-forwarded-for:"
    };
    const char *p = headers;
    int pos = 0;
    out[0] = 0;

    while (p && *p && pos < outsz - 8) {
        const char *eol = strstr(p, "\r\n");
        int len;
        size_t i;
        char line[300];
        int matched = 0;

        if (!eol) eol = p + strlen(p);
        len = (int)(eol - p);
        if (len > 0 && len < (int)sizeof(line)) {
            memcpy(line, p, (size_t)len);
            line[len] = 0;
            for (i = 0; i < sizeof(WANT) / sizeof(WANT[0]); i++) {
                size_t wl = strlen(WANT[i]);
                size_t j;
                int hit = 1;
                if ((size_t)len < wl) continue;
                for (j = 0; j < wl; j++) {
                    char a = line[j];
                    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                    if (a != WANT[i][j]) { hit = 0; break; }
                }
                if (!hit) continue;
                if (pos) pos += snprintf(out + pos, (size_t)(outsz - pos), "  |  ");
                pos += snprintf(out + pos, (size_t)(outsz - pos), "%s", line);
                matched = 1;
                break;
            }
        }
        (void)matched;
        if (!*eol) break;
        p = eol + 2;
    }
    out[outsz - 1] = 0;
}

#endif /* PW_HOOKUTIL_H */
