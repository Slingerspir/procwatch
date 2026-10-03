/* pw_hooks.h - the hook engine.
 *
 * Strategy: every Win32 call we care about is imported by name from kernelbase
 * / advapi32 / ws2_32 / wininet / winhttp / shell32. We walk the import address
 * table of every loaded module and repoint the entries that bind to one of our
 * targets. On x64 an IAT entry is a full 8-byte pointer, so a hook living in
 * our own DLL can be written into any module's table directly.
 *
 * We do NOT patch export tables. An export entry is a 32-bit RVA *relative to
 * the owning module*, so pointing it at code in a different module is not
 * representable: the value silently truncates and every caller that resolves
 * that export jumps into unmapped memory. Doing it to user32 is an instant
 * crash the moment anything themes a window. Coverage that the export table
 * would have given us is recovered by two cheaper means instead:
 *
 *   - hooking GetProcAddress, which hands out our hook for any dynamically
 *     resolved target (this is also what makes the "resolved at runtime"
 *     pattern visible in the log), and
 *   - hooking LoadLibrary*, so a module that appears after us gets its import
 *     table repointed as soon as it is loaded.
 *
 * Every patched slot is recorded so pw_hooks_remove() can put the original
 * pointer back. */
#ifndef PW_HOOKS_H
#define PW_HOOKS_H

#include "pw_common.h"

/* A single API usually has more than one address in a process. On Windows 11
 * kernel32!CreateFileW is a real stub and kernelbase!CreateFileW is the
 * implementation, and they are different addresses; a module built against the
 * classic import library binds the former, a module built against the api-ms-*
 * API sets binds the latter. Matching only one of them silently misses half the
 * process, so every address a name resolves to is recorded and every one of
 * them is matched. */
#define PW_MAX_ALT 8

typedef struct {
    const char *name;        /* exported name, e.g. "CreateFileW" */
    void       *hook;        /* our replacement */
    void      **orig;        /* primary resolved address; also what we call */
    const char *group;       /* "kernelbase" / "ws2_32" ... - documentation only */
    int         redirects;   /* times GetProcAddress was redirected to `hook` */
    int         iat_hits;    /* import entries repointed at `hook` so far */
    void       *alt[PW_MAX_ALT]; /* other addresses the same name resolves to */
    int         nalt;
} PW_HOOK;

/* Defined in pw_hookapi.c */
extern PW_HOOK    pw_hook_table[];
extern const int  pw_hook_table_count;

/* One-time setup of the hook layer's own bookkeeping (the handle -> path
 * cache). Called from the injection thread before pw_hooks_install(). */
void pw_hookapi_init(void);

/* Install everything. Returns the number of hooks whose original was resolved
 * (0 means the engine failed outright). Runs on the caller's thread and must be
 * called with pw_suppress_enter() held. */
int  pw_hooks_install(void);

/* Restore every patched byte. Safe to call once; afterwards the process runs
 * completely unhooked (our threads keep running but observe nothing). */
void pw_hooks_remove(void);

/* Called from the LoadLibrary hooks: repoint the imports of a module that
 * appeared after we installed. Cheap no-op for our own module. */
void pw_hooks_on_module_load(HMODULE mod);

/* If `addr` is one of the addresses we hook, return our replacement and count
 * the redirect; otherwise return NULL. This is what makes a dynamically
 * resolved API run through us too. */
void *pw_hooks_redirect(void *addr);

/* Total number of GetProcAddress calls redirected so far. */
int  pw_hooks_redirect_count(void);

/* Re-walk every loaded module's IAT (used once at startup and on demand). */
int  pw_hooks_rescan(void);

int  pw_hooks_installed_count(void);
int  pw_hooks_patch_site_count(void);

#endif /* PW_HOOKS_H */
