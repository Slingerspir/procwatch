@echo off
setlocal enabledelayedexpansion
rem ProcWatch - build script for cmd.exe (the Makefile does the same thing).
rem Requires MinGW-w64 gcc (x86_64). Put it on PATH or edit GCC below.

set GCC=gcc
where %GCC% >nul 2>nul
if errorlevel 1 (
    if exist "D:\mingw64\bin\gcc.exe" set GCC=D:\mingw64\bin\gcc.exe
)
where %GCC% >nul 2>nul
if errorlevel 1 (
    echo [!] gcc not found. Install MinGW-w64 and put it on PATH,
    echo     or edit the GCC variable at the top of this script.
    exit /b 1
)

set CFLAGS=-O2 -Wall -Wextra -Wno-unused-parameter -std=gnu11 -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 -finput-charset=UTF-8 -fexec-charset=UTF-8 -Isrc -Ibuild\gen

rem -static keeps MinGW's C runtime out of the picture: linked dynamically it
rem becomes a separate DLL that only exists inside the toolchain directory.
set LDFLAGS=-static

if not exist build\gen mkdir build\gen
if not exist dist mkdir dist

echo [1/4] building the asset embedder...
%GCC% -O2 -o build\embed.exe tools\embed.c || exit /b 1

echo [2/4] embedding web assets...
build\embed.exe web\webui.html build\gen\pw_webui_html.h pw_webui_html || exit /b 1
build\embed.exe web\hub.html   build\gen\pw_hub_html.h   pw_hub_html   || exit /b 1

echo [3/4] building ProcWatch.dll...
%GCC% %CFLAGS% %LDFLAGS% -shared -o dist\ProcWatch.dll ^
    src\pw_util.c src\pw_events.c src\pw_config.c src\pw_state.c src\pw_rules.c ^
    src\pw_json.c src\pw_hooks.c src\pw_hookapi.c src\pw_hookapi_winhttp.c ^
    src\pw_gui.c src\pw_http.c src\pw_dll.c ^
    -lkernel32 -luser32 -ladvapi32 -lws2_32 -lwininet -lwinhttp -lcomctl32 -lgdi32 -lshell32 || exit /b 1

echo [4/4] building injector.exe and testtarget.exe...
%GCC% %CFLAGS% %LDFLAGS% -o dist\injector.exe src\injector.c src\pw_config.c src\pw_util.c ^
    -lkernel32 -luser32 -ladvapi32 -lws2_32 || exit /b 1
%GCC% %CFLAGS% %LDFLAGS% -o dist\testtarget.exe src\testtarget.c ^
    -lkernel32 -luser32 -lws2_32 -lwinhttp -lwininet || exit /b 1

echo.
echo   build complete - artifacts in dist\
echo     ProcWatch.dll    injectable monitor module (x64)
echo     injector.exe     injector / aggregation hub
echo     testtarget.exe   behaviour test target
echo.
echo   try:
echo     dist\injector.exe --exe dist\testtarget.exe --hub
echo.
endlocal
