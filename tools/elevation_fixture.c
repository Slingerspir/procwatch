/* Test fixture: a program whose manifest demands administrator rights.
 *
 * Used to exercise injector.exe's handling of ERROR_ELEVATION_REQUIRED (740)
 * without having to point it at some real elevated program on the machine.
 *
 *   windres tools/elevation_fixture.rc -O coff -o build/elevation_fixture.res
 *        (see tools/elevation_fixture.rc for the manifest reference)
 *   gcc -o build/elevation_fixture.exe tools/elevation_fixture.c build/elevation_fixture.res
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    printf("elevation fixture: running elevated, pid %lu\n",
           (unsigned long)GetCurrentProcessId());
    printf("this window closes in 5 seconds\n");
    Sleep(5000);
    return 0;
}
