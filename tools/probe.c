/* tools/probe.c - diagnostic: does GetProcAddress agree with what the loader
 * bound into an import table?
 *
 * ProcWatch matches import entries by comparing the bound pointer against
 * GetProcAddress(kernel32, name). If those two disagree for some exports, the
 * corresponding hook silently matches nothing. This prints both for a set of
 * names, plus the address actually sitting in this module's own IAT.
 *
 *   gcc -o build/probe.exe tools/probe.c
 */
#include <windows.h>
#include <stdio.h>

static void *iat_entry(HMODULE mod, const char *want)
{
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *imp;

    if (!dir->VirtualAddress) return NULL;
    imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + dir->VirtualAddress);
    for (; imp->Name; imp++) {
        IMAGE_THUNK_DATA *oft, *ft;
        if (!imp->OriginalFirstThunk) continue;
        oft = (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk);
        ft  = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        for (; oft->u1.AddressOfData; oft++, ft++) {
            IMAGE_IMPORT_BY_NAME *ibn;
            if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            ibn = (IMAGE_IMPORT_BY_NAME *)(base + oft->u1.AddressOfData);
            if (lstrcmpiA((LPCSTR)ibn->Name, want) == 0)
                return (void *)(ULONG_PTR)ft->u1.Function;
        }
    }
    return NULL;
}

int main(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE kb  = GetModuleHandleA("kernelbase.dll");
    HMODULE self = GetModuleHandleA(NULL);
    static const char *names[] = {
        "CreateFileW", "CreateFileA", "WriteFile", "ReadFile",
        "DeleteFileW", "DeleteFileA", "MoveFileExW", "CopyFileW",
        "FindFirstFileW", "FindFirstFileA", "CreateDirectoryW", "CreateDirectoryA",
        "RegSetValueExW", "RegSetValueExA", "RegOpenKeyExW", "RegOpenKeyExA",
        "VirtualAlloc", "CreateProcessW", "CreateProcessA", "LoadLibraryA",
        "LoadLibraryW", "CloseHandle", "VirtualProtect"
    };
    int i;

    printf("%-20s %-18s %-18s %-18s %s\n", "name", "kernel32", "kernelbase", "own IAT", "verdict");
    for (i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
        void *a = (void *)GetProcAddress(k32, names[i]);
        void *b = kb ? (void *)GetProcAddress(kb, names[i]) : NULL;
        void *c = iat_entry(self, names[i]);
        const char *verdict = "ok";
        if (c && a && c != a) verdict = "IAT != kernel32 !!";
        if (a && b && a != b) verdict = "kernel32 != kernelbase !!";
        printf("%-20s %-18p %-18p %-18p %s\n", names[i], a, b, c, verdict);
    }
    return 0;
}
