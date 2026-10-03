/* pw_hooks.c - import address table patching and clean removal.
 *
 * See pw_hooks.h for why export tables are deliberately left alone.
 *
 * Two facts drive the implementation:
 *
 *  - An import entry is a native pointer (8 bytes here). Writing a hook that
 *    lives in another module is therefore exact, not truncated.
 *  - The system modules we *do* patch targets inside (kernel32, kernelbase,
 *    advapi32, ...) also contain the implementations that call each other
 *    internally. Their own import tables are skipped, otherwise an ANSI call
 *    that forwards to its wide counterpart would be reported twice. Every other
 *    module - the CRT, the application's own DLLs - is patched, and that is
 *    where the interesting traffic is. */
#include "pw_hooks.h"
#include "pw_state.h"
#include "pw_util.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    ULONG_PTR *slot;
    ULONG_PTR  old;
} PATCH_SITE;

#define MAX_SITES 65536

static PATCH_SITE       g_sites[MAX_SITES];
static int              g_nsites = 0;
static CRITICAL_SECTION g_sites_cs;
static int              g_sites_cs_ready = 0;
static int              g_installed = 0;
static volatile long    g_redirects = 0;

/* Modules whose own import tables we leave untouched. */
static const char *const CORE_MODULES[] = {
    "kernel32.dll", "kernelbase.dll", "advapi32.dll", "ws2_32.dll",
    "wininet.dll",  "winhttp.dll",    "shell32.dll",  "user32.dll",
    "mswsock.dll",  "iphlpapi.dll",   "dnsapi.dll",   "crypt32.dll",
    "bcrypt.dll",   "ole32.dll",      "shlwapi.dll",  "secur32.dll",
    "userenv.dll",  "winmm.dll",      "version.dll",  "ntdll.dll",
};
#define N_CORE ((int)(sizeof(CORE_MODULES) / sizeof(CORE_MODULES[0])))

/* Searched in order when resolving the address a caller would receive. */
static const char *const LOOKUP_MODULES[] = {
    "kernel32.dll", "kernelbase.dll", "advapi32.dll", "ws2_32.dll",
    "wininet.dll",  "winhttp.dll",    "shell32.dll",  "user32.dll",
    "mswsock.dll",  "iphlpapi.dll",   "dnsapi.dll",   "crypt32.dll",
    "bcrypt.dll",   "ole32.dll",      "shlwapi.dll",  "userenv.dll",
    "secur32.dll",  "ntdll.dll",
};
#define N_LOOKUP ((int)(sizeof(LOOKUP_MODULES) / sizeof(LOOKUP_MODULES[0])))

/* ------------------------------------------------------------------ helpers */

static IMAGE_NT_HEADERS *nt_of(HMODULE mod)
{
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    ULONG_PTR p = (ULONG_PTR)mod;

    if (p < 0x10000) return NULL;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x10000000) return NULL;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if ((ULONG_PTR)nt < p) return NULL;
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;
    return nt;
}

static int is_core_module(const char *base)
{
    int i;
    for (i = 0; i < N_CORE; i++)
        if (pw_streqi(base, CORE_MODULES[i])) return 1;
    return 0;
}

static void record_site(ULONG_PTR *slot, ULONG_PTR oldValue)
{
    int i;
    if (!g_sites_cs_ready) return;
    EnterCriticalSection(&g_sites_cs);
    for (i = 0; i < g_nsites; i++) {
        if (g_sites[i].slot == slot) { LeaveCriticalSection(&g_sites_cs); return; }
    }
    if (g_nsites < MAX_SITES) {
        g_sites[g_nsites].slot = slot;
        g_sites[g_nsites].old  = oldValue;
        g_nsites++;
    }
    LeaveCriticalSection(&g_sites_cs);
}

/* ------------------------------------------------------- import table patch */

/* Is `name` one of the APIs we hook? Used by the diagnostic path only. */
static int is_hook_name(const char *name)
{
    int i;
    for (i = 0; i < pw_hook_table_count; i++)
        if (pw_streqi(pw_hook_table[i].name, name)) return 1;
    return 0;
}

static PW_HOOK *hook_for_address(ULONG_PTR addr);   /* defined below */
static PW_HOOK *hook_for_name(const char *name);    /* defined below */

/* Repoint every import entry of `mod` that still binds to one of our originals.
 * The thunk arrays live outside the import data directory, so the span to make
 * writable is computed first and protected once, rather than per entry.
 *
 * `reportUnmatched` is set for the main executable: an import of an API we hook
 * whose bound address matches none of that name's known forms is the one case
 * where coverage silently disappears, and it is worth naming explicitly. */
static int iat_patch_module_ex(HMODULE mod, int reportUnmatched)
{
    IMAGE_NT_HEADERS *nt = nt_of(mod);
    IMAGE_DATA_DIRECTORY *dir;
    IMAGE_IMPORT_DESCRIPTOR *imp;
    BYTE *lo = NULL, *hi = NULL;
    DWORD oldProt = 0;
    int patched = 0;

    if (!nt || mod == g_self) return 0;

    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->VirtualAddress == 0 || dir->Size == 0) return 0;

    /* Pass 1: the span covering every first-thunk array. */
    imp = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)mod + dir->VirtualAddress);
    for (; imp->Name; imp++) {
        IMAGE_THUNK_DATA *t;
        if (imp->FirstThunk == 0) continue;
        t = (IMAGE_THUNK_DATA *)((BYTE *)mod + imp->FirstThunk);
        while (t->u1.Function) t++;
        if (!lo || (BYTE *)t < lo) lo = (BYTE *)t;
        if (!hi || (BYTE *)(t + 1) > hi) hi = (BYTE *)(t + 1);
    }
    if (!lo) return 0;

    {
        SYSTEM_INFO si;
        ULONG_PTR start, end;
        GetSystemInfo(&si);
        start = (ULONG_PTR)lo & ~(ULONG_PTR)(si.dwPageSize - 1);
        end   = ((ULONG_PTR)hi + si.dwPageSize - 1) & ~(ULONG_PTR)(si.dwPageSize - 1);
        if (!VirtualProtect((LPVOID)start, end - start, PAGE_READWRITE, &oldProt))
            return 0;

        imp = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)mod + dir->VirtualAddress);
        for (; imp->Name; imp++) {
            IMAGE_THUNK_DATA *t, *oft;
            if (imp->FirstThunk == 0) continue;
            t = (IMAGE_THUNK_DATA *)((BYTE *)mod + imp->FirstThunk);
            oft = imp->OriginalFirstThunk
                    ? (IMAGE_THUNK_DATA *)((BYTE *)mod + imp->OriginalFirstThunk) : NULL;
            for (; t->u1.Function; t++, (oft ? oft++ : oft)) {
                ULONG_PTR addr = (ULONG_PTR)t->u1.Function;
                const char *iname = NULL;
                PW_HOOK *h;

                if (oft && !(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                    iname = (const char *)((IMAGE_IMPORT_BY_NAME *)
                                           ((BYTE *)mod + oft->u1.AddressOfData))->Name;

                /* Primary match is by name; the address lookup is the fallback
                 * for ordinal imports and descriptors that carry no name
                 * table. */
                h = hook_for_name(iname);
                if (!h) h = hook_for_address(addr);

                if (h && h->hook && *h->orig) {
                    t->u1.Function = (ULONG_PTR)h->hook;
                    /* Read back: if the page was not actually writable the
                     * store would be lost, and that must not pass silently. */
                    if ((ULONG_PTR)t->u1.Function != (ULONG_PTR)h->hook)
                        pw_trace("  WRITE FAILED: %s", iname ? iname : "(ordinal)");
                    else {
                        record_site(&t->u1.Function, addr);
                        h->iat_hits++;
                        patched++;
                    }
                } else if (reportUnmatched && is_hook_name(iname)) {
                    /* An API we hook is imported by name but matched nothing:
                     * this is the one case where coverage silently disappears. */
                    pw_trace("  UNMATCHED import: %s (from %s)", iname,
                             (const char *)mod + imp->Name);
                }
            }
        }
        VirtualProtect((LPVOID)start, end - start, oldProt, &oldProt);
    }
    return patched;
}

/* --------------------------------------------------------------- resolution */

static int iat_patch_module(HMODULE mod)
{
    return iat_patch_module_ex(mod, 0);
}

/* Collect every distinct address `name` resolves to across the modules that
 * could own or forward it. See PW_MAX_ALT in the header for why one is not
 * enough. */
static int resolve_all(const char *name, void **out, int cap)
{
    int i, n = 0;
    for (i = 0; i < N_LOOKUP && n < cap; i++) {
        HMODULE m = GetModuleHandleA(LOOKUP_MODULES[i]);
        FARPROC p;
        int j, dup = 0;
        if (!m) continue;
        p = GetProcAddress(m, name);
        if (!p) continue;
        for (j = 0; j < n; j++)
            if (out[j] == (void *)p) { dup = 1; break; }
        if (!dup) out[n++] = (void *)p;
    }
    return n;
}

/* Does this address belong to any of a hook's known forms? */
static PW_HOOK *hook_for_address(ULONG_PTR addr)
{
    int i, k;
    for (i = 0; i < pw_hook_table_count; i++) {
        PW_HOOK *h = &pw_hook_table[i];
        if (*h->orig && (ULONG_PTR)*h->orig == addr) return h;
        for (k = 0; k < h->nalt; k++)
            if ((ULONG_PTR)h->alt[k] == addr) return h;
    }
    return NULL;
}

/* Look a hook up by the name the importing module used. This is the primary
 * match: the name in the import table is exactly what we hook, so it cannot be
 * thrown off by which module the loader happened to bind the call to. */
static PW_HOOK *hook_for_name(const char *name)
{
    int i;
    if (!name) return NULL;
    for (i = 0; i < pw_hook_table_count; i++)
        if (pw_streqi(pw_hook_table[i].name, name)) return &pw_hook_table[i];
    return NULL;
}

/* -------------------------------------------------------------- module walk */

#define MAX_MODS 1024

static int enum_modules(HMODULE *out, int cap)
{
    HANDLE snap;
    MODULEENTRY32W me;
    int n = 0, i, seenSelf = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                    GetCurrentProcessId());
    if (snap != INVALID_HANDLE_VALUE) {
        memset(&me, 0, sizeof(me));
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                if (n < cap) out[n++] = (HMODULE)me.modBaseAddr;
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }

    for (i = 0; i < n; i++) if (out[i] == g_self) seenSelf = 1;
    if (!seenSelf && g_self && n < cap) out[n++] = g_self;

    return n;
}

/* ------------------------------------------------------------------- public */

int pw_hooks_patch_site_count(void) { return g_nsites; }
int pw_hooks_redirect_count(void) { return (int)g_redirects; }

int pw_hooks_installed_count(void)
{
    int i, n = 0;
    for (i = 0; i < pw_hook_table_count; i++)
        if (*pw_hook_table[i].orig) n++;
    return n;
}

void *pw_hooks_redirect(void *addr)
{
    PW_HOOK *h;
    if (!addr || !g_installed) return NULL;
    h = hook_for_address((ULONG_PTR)addr);
    if (!h) return NULL;
    h->redirects++;
    InterlockedIncrement(&g_redirects);
    return h->hook;
}

int pw_hooks_install(void)
{
    HMODULE mods[MAX_MODS];
    int nmods, i, m, resolved = 0, iatHits = 0, skipped = 0;

    if (!g_sites_cs_ready) {
        InitializeCriticalSection(&g_sites_cs);
        g_sites_cs_ready = 1;
    }

    /* 1. Resolve every original BEFORE patching anything: these must be the
     *    addresses already bound in the import tables of loaded modules. */
    for (i = 0; i < pw_hook_table_count; i++) {
        PW_HOOK *h = &pw_hook_table[i];
        void *addrs[PW_MAX_ALT + 4];
        int n = resolve_all(h->name, addrs, PW_MAX_ALT + 4);
        int k;

        h->nalt = 0;
        if (n == 0) {
            pw_trace("  unresolved: %s", h->name);
            continue;
        }
        *h->orig = addrs[0];
        for (k = 1; k < n && h->nalt < PW_MAX_ALT; k++)
            h->alt[h->nalt++] = addrs[k];
        resolved++;
    }
    pw_trace("install: resolved %d/%d originals", resolved, pw_hook_table_count);

    /* 2. Repoint the import tables of everything already loaded. */
    nmods = enum_modules(mods, MAX_MODS);
    pw_trace("install: %d loaded modules", nmods);
    for (m = 0; m < nmods; m++) {
        char path[MAX_PATH];
        if (mods[m] == g_self) continue;
        if (!GetModuleFileNameA(mods[m], path, sizeof(path))) continue;
        if (is_core_module(pw_base_name(path))) { skipped++; continue; }
        {
            int hits = iat_patch_module_ex(mods[m], mods[m] == GetModuleHandleA(NULL));
            iatHits += hits;
            if (hits) pw_trace("  iat: %s -> %d entries", pw_base_name(path), hits);
        }
    }

    g_installed = 1;

    /* Report the hooks that matched nothing: with 60+ targets it is not obvious
     * by inspection which ones an application never imports by name, and a hook
     * with zero matches is exactly the case worth knowing about. */
    for (i = 0; i < pw_hook_table_count; i++) {
        PW_HOOK *h = &pw_hook_table[i];
        if (h->iat_hits == 0)
            pw_trace("  no import matched: %s%s", h->name,
                     *h->orig ? "" : " (unresolved)");
    }

    pw_trace("install: %d import entries patched (skipped %d core modules)",
             iatHits, skipped);

    {
        char detail[320];
        _snprintf(detail, sizeof(detail),
                  "挂钩 %d 个 API；改写 %d 个模块的导入表，共 %d 处指针"
                  "（跳过 %d 个系统模块自身导入表）",
                  resolved, nmods - skipped, g_nsites, skipped);
        detail[sizeof(detail) - 1] = 0;
        pw_report_force(PW_CAT_SYS, PW_LVL_INFO, "InstallHooks",
                        g_exe_name, detail, 0, 0);
    }
    return resolved;
}

void pw_hooks_on_module_load(HMODULE mod)
{
    char path[MAX_PATH];

    if (!g_installed || !mod || mod == g_self) return;
    if (!GetModuleFileNameA(mod, path, sizeof(path))) return;
    if (is_core_module(pw_base_name(path))) return;
    if (iat_patch_module(mod) > 0)
        pw_trace("module loaded and patched: %s", pw_base_name(path));
}

int pw_hooks_rescan(void)
{
    HMODULE mods[MAX_MODS];
    int nmods, m, hits = 0;
    if (!g_installed) return 0;
    nmods = enum_modules(mods, MAX_MODS);
    for (m = 0; m < nmods; m++) {
        char path[MAX_PATH];
        if (mods[m] == g_self) continue;
        if (!GetModuleFileNameA(mods[m], path, sizeof(path))) continue;
        if (is_core_module(pw_base_name(path))) continue;
        hits += iat_patch_module(mods[m]);
    }
    return hits;
}

void pw_hooks_remove(void)
{
    int i;

    if (!g_sites_cs_ready) return;
    EnterCriticalSection(&g_sites_cs);
    for (i = g_nsites - 1; i >= 0; i--) {
        DWORD oldProt = 0;
        if (!g_sites[i].slot) continue;
        if (VirtualProtect(g_sites[i].slot, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProt)) {
            *g_sites[i].slot = g_sites[i].old;
            VirtualProtect(g_sites[i].slot, sizeof(ULONG_PTR), oldProt, &oldProt);
        }
    }
    g_nsites = 0;
    LeaveCriticalSection(&g_sites_cs);

    g_installed = 0;
    for (i = 0; i < pw_hook_table_count; i++) {
        pw_hook_table[i].redirects = 0;
        pw_hook_table[i].iat_hits = 0;
    }
}
