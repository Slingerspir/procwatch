/*
 * pw_common.h - ProcWatch shared definitions (DLL / injector / hub / test target)
 *
 * ProcWatch: an in-process behaviour monitor. Injected into a target process it
 * patches the export tables of the core Win32 modules plus the IATs of every
 * already-loaded module, so that file / registry / network / HTTP / process /
 * module / memory activity is reported to an in-process window and a WebUI.
 */
#ifndef PW_COMMON_H
#define PW_COMMON_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

#define PW_VERSION      "1.0.0"
#define PW_PRODUCT      "ProcWatch"

/* Default TCP port for the in-process WebUI. Ports are probed upward from here
 * per process, so several injected processes can coexist. */
#define PW_PORT_BASE    8710
#define PW_HUB_PORT     8700

/* ---------------------------------------------------------------- categories */
enum {
    PW_CAT_FILE = 1,
    PW_CAT_REG,
    PW_CAT_NET,
    PW_CAT_HTTP,
    PW_CAT_PROC,
    PW_CAT_MOD,
    PW_CAT_MEM,
    PW_CAT_SYS
};

enum {
    PW_LVL_INFO = 0,   /* normal activity */
    PW_LVL_WARN,       /* noteworthy */
    PW_LVL_SUSPECT     /* matches a risk rule */
};

#define PW_CAT_NAMES {"", "文件", "注册表", "网络", "HTTP", "进程", "模块", "内存", "系统"}
#define PW_LVL_NAMES {"信息", "注意", "可疑"}

/* --------------------------------------------------------------------- event */
#define PW_API_LEN  40
#define PW_TGT_LEN  384
#define PW_DET_LEN  320

typedef struct {
    unsigned long long seq;      /* monotonic, starts at 1 */
    unsigned long long ts;       /* unix time, milliseconds */
    unsigned int  tid;
    unsigned char cat;           /* PW_CAT_* */
    unsigned char lvl;           /* PW_LVL_* */
    unsigned short flags;        /* PW_EF_* */
    unsigned int  size;          /* payload byte count, when meaningful */
    int           result;        /* return value / win32 error */
    char api[PW_API_LEN];        /* "CreateFileW" */
    char target[PW_TGT_LEN];     /* path / url / key / cmdline */
    char detail[PW_DET_LEN];     /* extra: access mask, preview, status line */
} PW_EVENT;

#define PW_EF_ENTER   0x0001     /* event logged on entry (result unknown) */
#define PW_EF_FAILED  0x0002
#define PW_EF_PREVIEW 0x0004     /* detail holds a data preview */

/* -------------------------------------------------------------------- config */
typedef struct {
    int  gui;            /* create the in-process window            (1) */
    int  http;           /* run the embedded web server             (1) */
    int  port;           /* 0 = auto-probe from PW_PORT_BASE          */
    int  log_file;       /* mirror events to a jsonl file           (0) */
    int  verbose;        /* also log high-frequency noise           (0) */
    int  risk;           /* enable the risk rule engine             (1) */
    int  previews;       /* capture payload previews                (0) */
    int  wininet;        /* hook wininet/winhttp                    (1) */
    int  stack_trace;    /* record caller return address           (1) */
    unsigned int ring;   /* ring capacity in events              (8192) */
    int  disk_free_mb;   /* stop file logging below this            (64) */
    char log_dir[MAX_PATH];
    char config_file[MAX_PATH];
} PW_CONFIG;

/* ------------------------------------------------------------------ discovery
 * %TEMP%\ProcWatch\<pid>.json is written by the DLL at startup and deleted on
 * detach so the hub can enumerate live instances. */
#define PW_DIR_NAME  "ProcWatch"

/* ------------------------------------------------------------- config payload
 * An injected DLL receives no arguments, so options travel out of band:
 *   - launched children get the PROCWATCH_OPTS environment variable
 *   - explicit PID injection drops a "pending.ini" file we consume once
 * Both use "key=value,key=value" syntax, parsed by pw_config_parse(). */
#define PW_OPTS_ENV  "PROCWATCH_OPTS"
#define PW_PENDING   "pending.ini"

/* The DLL signals this event once its hooks are installed. The injector creates
 * it before injecting and resumes a suspended target only after it fires.
 *
 * This matters more than it looks. Compilers routinely hoist an IAT load out of
 * a function ("mov __imp_CreateFileA(%rip),%r12" at the top, then every call
 * through %r12), so a target that starts running before the import tables are
 * repointed keeps calling the original function for the rest of that function's
 * lifetime. Waiting for this event before ResumeThread is what makes an
 * auto-launched target fully instrumented. */
#define PW_READY_EVENT_FMT "Local\\ProcWatchReady_%lu"

#endif /* PW_COMMON_H */
