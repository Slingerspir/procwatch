/* pw_hookapi_http.h - WinHTTP hooks, defined in their own translation unit.
 *
 * MinGW's winhttp.h and wininet.h each declare INTERNET_SCHEME and
 * URL_COMPONENTS, with different definitions, and cannot both be included from
 * one file. The WinINet hooks therefore keep wininet.h, and these keep
 * winhttp.h. HINTERNET is LPVOID and INTERNET_PORT is an unsigned short, so the
 * prototypes here are ABI-identical to the real ones while avoiding the header
 * dependency entirely. */
#ifndef PW_HOOKAPI_HTTP_H
#define PW_HOOKAPI_HTTP_H

#include "pw_common.h"

void *WINAPI pw_hook_WinHttpOpen(LPCWSTR agent, DWORD access, LPCWSTR proxy,
                                 LPCWSTR bypass, DWORD flags);
void *WINAPI pw_hook_WinHttpConnect(void *session, LPCWSTR server,
                                    unsigned short port, DWORD reserved);
void *WINAPI pw_hook_WinHttpOpenRequest(void *conn, LPCWSTR verb, LPCWSTR object,
                                        LPCWSTR version, LPCWSTR referrer,
                                        LPCWSTR *acceptTypes, DWORD flags);
BOOL  WINAPI pw_hook_WinHttpSendRequest(void *req, LPCWSTR headers, DWORD headersLen,
                                        LPVOID optional, DWORD optionalLen,
                                        DWORD totalLen, DWORD_PTR ctx);
BOOL  WINAPI pw_hook_WinHttpReceiveResponse(void *req, LPVOID reserved);
BOOL  WINAPI pw_hook_WinHttpSetOption(void *h, DWORD option, LPVOID buf, DWORD len);
BOOL  WINAPI pw_hook_WinHttpGetProxyForUrl(void *session, LPCWSTR url,
                                           void *options, void *info);
BOOL  WINAPI pw_hook_WinHttpGetIEProxyConfigForCurrentUser(void *config);

/* Resolved originals, owned by pw_hookapi_winhttp.c. The hook table stores the
 * address of each of these so pw_hooks_install() can fill them in. */
extern void *(WINAPI *pw_real_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
extern void *(WINAPI *pw_real_WinHttpConnect)(void *, LPCWSTR, unsigned short, DWORD);
extern void *(WINAPI *pw_real_WinHttpOpenRequest)(void *, LPCWSTR, LPCWSTR, LPCWSTR,
                                                  LPCWSTR, LPCWSTR *, DWORD);
extern BOOL  (WINAPI *pw_real_WinHttpSendRequest)(void *, LPCWSTR, DWORD, LPVOID,
                                                  DWORD, DWORD, DWORD_PTR);
extern BOOL  (WINAPI *pw_real_WinHttpReceiveResponse)(void *, LPVOID);
extern BOOL  (WINAPI *pw_real_WinHttpSetOption)(void *, DWORD, LPVOID, DWORD);
extern BOOL  (WINAPI *pw_real_WinHttpGetProxyForUrl)(void *, LPCWSTR, void *, void *);
extern BOOL  (WINAPI *pw_real_WinHttpGetIEProxyConfigForCurrentUser)(void *);

#endif /* PW_HOOKAPI_HTTP_H */
