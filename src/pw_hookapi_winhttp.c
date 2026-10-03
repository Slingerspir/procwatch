/* pw_hookapi_winhttp.c - WinHTTP hooks.
 *
 * Separate translation unit because MinGW's winhttp.h and wininet.h cannot be
 * included together. The resolved originals are non-static so the hook table in
 * pw_hookapi.c can point at them. */
#include "pw_hooks.h"
#include "pw_state.h"
#include "pw_hookutil.h"
#include "pw_hookapi_http.h"
#include "pw_util.h"
#include <winhttp.h>
#include <string.h>

void *(WINAPI *pw_real_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) = NULL;
void *(WINAPI *pw_real_WinHttpConnect)(void *, LPCWSTR, unsigned short, DWORD) = NULL;
void *(WINAPI *pw_real_WinHttpOpenRequest)(void *, LPCWSTR, LPCWSTR, LPCWSTR,
                                           LPCWSTR, LPCWSTR *, DWORD) = NULL;
BOOL  (WINAPI *pw_real_WinHttpSendRequest)(void *, LPCWSTR, DWORD, LPVOID,
                                           DWORD, DWORD, DWORD_PTR) = NULL;
BOOL  (WINAPI *pw_real_WinHttpReceiveResponse)(void *, LPVOID) = NULL;
BOOL  (WINAPI *pw_real_WinHttpSetOption)(void *, DWORD, LPVOID, DWORD) = NULL;
BOOL  (WINAPI *pw_real_WinHttpGetProxyForUrl)(void *, LPCWSTR, void *, void *) = NULL;
BOOL  (WINAPI *pw_real_WinHttpGetIEProxyConfigForCurrentUser)(void *) = NULL;

void *WINAPI pw_hook_WinHttpOpen(LPCWSTR agent, DWORD access, LPCWSTR proxy,
                                 LPCWSTR bypass, DWORD flags)
{
    DWORD err = GetLastError();
    HINTERNET h;
    int obs = pw_observing();

    h = (HINTERNET)pw_real_WinHttpOpen(agent, access, proxy, bypass, flags);
    if (obs) {
        char ua[300], px[300], det[PW_DET_LEN];
        pw_wide_to_utf8(agent, ua, sizeof(ua));
        pw_wide_to_utf8(proxy, px, sizeof(px));
        pw_fmt(det, sizeof(det), "User-Agent: %s", ua[0] ? ua : "(默认)");
        if (access == WINHTTP_ACCESS_TYPE_NAMED_PROXY) {
            pw_str_cat(det, sizeof(det), "  |  命名代理: ");
            pw_str_cat(det, sizeof(det), px[0] ? px : "(未提供)");
        } else if (access == WINHTTP_ACCESS_TYPE_NO_PROXY) {
            pw_str_cat(det, sizeof(det), "  |  不使用代理");
        } else {
            pw_str_cat(det, sizeof(det), "  |  自动发现代理");
        }
        pw_report(PW_CAT_HTTP, PW_LVL_INFO, "WinHttpOpen",
                  ua[0] ? ua : "(WinHTTP 会话)", det, 0, 0);
    }
    SetLastError(err);
    return h;
}

void *WINAPI pw_hook_WinHttpConnect(void *session, LPCWSTR server,
                                    unsigned short port, DWORD reserved)
{
    DWORD err = GetLastError();
    HINTERNET h;
    int obs = pw_observing();

    h = (HINTERNET)pw_real_WinHttpConnect(session, server, port, reserved);
    if (obs) {
        char srv[256], tgt[PW_TGT_LEN];
        pw_wide_to_utf8(server, srv, sizeof(srv));
        pw_fmt(tgt, sizeof(tgt), "%s:%u", srv, (unsigned)port);
        pw_report(PW_CAT_HTTP, PW_LVL_INFO, "WinHttpConnect", tgt,
                  h ? "已连接" : "连接失败", 0, 0);
    }
    SetLastError(err);
    return h;
}

void *WINAPI pw_hook_WinHttpOpenRequest(void *conn, LPCWSTR verb, LPCWSTR object,
                                        LPCWSTR version, LPCWSTR referrer,
                                        LPCWSTR *acceptTypes, DWORD flags)
{
    DWORD err = GetLastError();
    HINTERNET h;
    int obs = pw_observing();

    h = (HINTERNET)pw_real_WinHttpOpenRequest(conn, verb, object, version,
                                              referrer, acceptTypes, flags);
    if (obs) {
        char v[32], o[PW_TGT_LEN], det[PW_DET_LEN];
        pw_wide_to_utf8(verb, v, sizeof(v));
        pw_wide_to_utf8(object, o, sizeof(o));
        pw_fmt(det, sizeof(det), "%s %s%s", v[0] ? v : "GET", o,
               (flags & WINHTTP_FLAG_SECURE) ? "  |  HTTPS" : "  |  明文 HTTP");
        pw_report(PW_CAT_HTTP, PW_LVL_INFO, "WinHttpOpenRequest",
                  o[0] ? o : "/", det, 0, 0);
    }
    SetLastError(err);
    return h;
}

BOOL WINAPI pw_hook_WinHttpSendRequest(void *req, LPCWSTR headers, DWORD headersLen,
                                       LPVOID optional, DWORD optionalLen,
                                       DWORD totalLen, DWORD_PTR ctx)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = pw_observing();

    ok = pw_real_WinHttpSendRequest(req, headers, headersLen, optional,
                                    optionalLen, totalLen, ctx);
    if (obs) {
        char det[PW_DET_LEN];
        if (headers) {
            char h8[600];
            pw_wide_to_utf8(headers, h8, sizeof(h8));
            pw_summarise_headers(h8, det, sizeof(det));
        }
        if (!det[0]) pw_str_copy(det, sizeof(det), "发送 HTTP 请求");
        pw_report(PW_CAT_HTTP, ok ? PW_LVL_INFO : PW_LVL_WARN,
                  "WinHttpSendRequest", "(HTTP 请求)", det, optionalLen, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

BOOL WINAPI pw_hook_WinHttpReceiveResponse(void *req, LPVOID reserved)
{
    DWORD err = GetLastError();
    BOOL ok;
    DWORD code = 0, n = sizeof(code);
    int obs = pw_observing();

    ok = pw_real_WinHttpReceiveResponse(req, reserved);
    if (obs) {
        char det[PW_DET_LEN];
        code = 0;
        if (ok) {
            /* Reading the status code back is a plain query, and WinHttpQueryHeaders
             * is not one of the functions we hook, so there is no recursion. */
            n = sizeof(code);
            if (!WinHttpQueryHeaders((HINTERNET)req, WINHTTP_QUERY_STATUS_CODE,
                                     WINHTTP_HEADER_NAME_BY_INDEX, &code, &n,
                                     WINHTTP_NO_HEADER_INDEX))
                code = 0;
        }
        if (code) pw_fmt(det, sizeof(det), "收到响应，HTTP 状态码 %u", (unsigned)code);
        else      pw_str_copy(det, sizeof(det), ok ? "收到响应" : "响应失败");
        pw_report(PW_CAT_HTTP, ok ? PW_LVL_INFO : PW_LVL_WARN,
                  "WinHttpReceiveResponse", "(HTTP 响应)", det, 0, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

BOOL WINAPI pw_hook_WinHttpSetOption(void *h, DWORD option, LPVOID buf, DWORD len)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = pw_observing();

    ok = pw_real_WinHttpSetOption(h, option, buf, len);
    if (obs && option == WINHTTP_OPTION_PROXY) {
        char det[PW_DET_LEN];
        pw_str_copy(det, sizeof(det), "设置 WinHTTP 代理配置");
        if (buf && len >= sizeof(WINHTTP_PROXY_INFO)) {
            WINHTTP_PROXY_INFO *pi = (WINHTTP_PROXY_INFO *)buf;
            if (pi->lpszProxy) {
                char px[300];
                pw_wide_to_utf8(pi->lpszProxy, px, sizeof(px));
                pw_str_cat(det, sizeof(det), "  代理: ");
                pw_str_cat(det, sizeof(det), px);
            }
        }
        pw_report(PW_CAT_HTTP, PW_LVL_SUSPECT, "WinHttpSetOption",
                  "(WinHTTP 代理)", det, len, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

BOOL WINAPI pw_hook_WinHttpGetProxyForUrl(void *session, LPCWSTR url,
                                          void *options, void *info)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = pw_observing();
    char u[PW_TGT_LEN];

    pw_wide_to_utf8(url, u, sizeof(u));
    ok = pw_real_WinHttpGetProxyForUrl(session, url,
                                       (WINHTTP_AUTOPROXY_OPTIONS *)options,
                                       (WINHTTP_PROXY_INFO *)info);
    if (obs) {
        char det[PW_DET_LEN];
        pw_str_copy(det, sizeof(det), "查询该 URL 应使用的代理");
        if (ok && info) {
            WINHTTP_PROXY_INFO *pi = (WINHTTP_PROXY_INFO *)info;
            if (pi->lpszProxy) {
                char px[300];
                pw_wide_to_utf8(pi->lpszProxy, px, sizeof(px));
                pw_str_cat(det, sizeof(det), "  -> ");
                pw_str_cat(det, sizeof(det), px);
            }
        }
        pw_report(PW_CAT_HTTP, PW_LVL_INFO, "WinHttpGetProxyForUrl",
                  u[0] ? u : "(空)", det, 0, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}

BOOL WINAPI pw_hook_WinHttpGetIEProxyConfigForCurrentUser(void *config)
{
    DWORD err = GetLastError();
    BOOL ok;
    int obs = pw_observing();

    ok = pw_real_WinHttpGetIEProxyConfigForCurrentUser(config);
    if (obs) {
        char det[PW_DET_LEN];
        pw_str_copy(det, sizeof(det), "读取系统(IE)代理配置");
        if (ok && config) {
            WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *cfg =
                (WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *)config;
            if (cfg->lpszProxy) {
                char px[300];
                pw_wide_to_utf8(cfg->lpszProxy, px, sizeof(px));
                pw_str_cat(det, sizeof(det), "  -> ");
                pw_str_cat(det, sizeof(det), px);
            }
        }
        pw_report(PW_CAT_HTTP, PW_LVL_WARN, "WinHttpGetIEProxyConfigForCurrentUser",
                  "(系统代理)", det, 0, ok ? 0 : -1);
    }
    SetLastError(err);
    return ok;
}
