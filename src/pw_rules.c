/* pw_rules.c - a small, honest heuristic layer.
 *
 * These rules do not decide whether something is malware; they only mark the
 * handful of behaviours that analysts look at first (autostart persistence,
 * code dropped in a writable directory, interpreters launched with an encoded
 * command line, RWX memory, credential stores, raw outbound sockets).
 * Every hit is annotated with the reason so nothing is a black box.
 */
#include "pw_rules.h"
#include "pw_util.h"
#include <string.h>
#include "pw_lang.h"

/* --- autostart / persistence locations -------------------------------- */
static const char *const PERSIST[] = {
    "\\start menu\\programs\\startup\\",
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\currentversion\\policies\\explorer\\run",
    "\\winlogon",
    "\\image file execution options",
    "\\appinit_dlls",
    "\\system32\\tasks\\",
    "\\windows\\tasks\\",
    "\\services\\",
    "\\currentversion\\explorer\\shell folders",
    "\\currentversion\\explorer\\browser helper objects",
};
#define N_PERSIST ((int)(sizeof(PERSIST) / sizeof(PERSIST[0])))

/* --- credential and privacy sensitive stores -------------------------- */
static const char *const SECRETS[] = {
    "\\login data", "\\cookies", "\\web data", "\\logins.json",
    "\\key3.db", "\\key4.db", "\\signons.sqlite", "\\cert9.db",
    "\\local state", "\\wallet.dat", "\\electrum\\wallets",
    "\\.ssh\\id_rsa", "\\.ssh\\id_ed25519", "\\.ssh\\known_hosts",
    "\\microsoft\\credentials", "\\microsoft\\vault",
    "\\google\\chrome\\user data", "\\mozilla\\firefox\\profiles",
    "\\microsoft\\edge\\user data", "\\opera software\\",
    "\\sam$", "\\system32\\config\\sam", "\\system32\\config\\security",
    "\\ntds.dit",
};
#define N_SECRETS ((int)(sizeof(SECRETS) / sizeof(SECRETS[0])))

/* --- where droppers like to write ------------------------------------- */
static const char *const DROP_DIRS[] = {
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\downloads\\",
    "\\$recycle.bin\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\perflogs\\",
};
#define N_DROP ((int)(sizeof(DROP_DIRS) / sizeof(DROP_DIRS[0])))

static const char *const DROP_EXTS[] = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".lnk", ".pif", ".com", ".sys",
};
#define N_DROP_EXT ((int)(sizeof(DROP_EXTS) / sizeof(DROP_EXTS[0])))

/* --- interpreters worth a second look --------------------------------- */
static const char *const LOLBINS[] = {
    "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec",
    "installutil", "regasm", "regsvcs", "wmic", "schtasks", "at.exe",
    "curl", "nslookup", "netsh", "sc.exe", "net.exe", "psexec",
};
#define N_LOLBIN ((int)(sizeof(LOLBINS) / sizeof(LOLBINS[0])))

static void mark(PW_EVENT *ev, const char *why)
{
    ev->lvl = PW_LVL_SUSPECT;
    if (ev->detail[0]) pw_str_cat(ev->detail, sizeof(ev->detail), "  ");
    pw_str_cat(ev->detail, sizeof(ev->detail), L("[规则] "));
    pw_str_cat(ev->detail, sizeof(ev->detail), why);
}

static void note(PW_EVENT *ev, const char *why)
{
    if (ev->lvl < PW_LVL_WARN) ev->lvl = PW_LVL_WARN;
    if (ev->detail[0]) pw_str_cat(ev->detail, sizeof(ev->detail), "  ");
    pw_str_cat(ev->detail, sizeof(ev->detail), L("[注] "));
    pw_str_cat(ev->detail, sizeof(ev->detail), why);
}

static int is_drop_path(const char *p)
{
    int i, dirOk = 0;
    for (i = 0; i < N_DROP; i++)
        if (pw_contains_i(p, DROP_DIRS[i])) { dirOk = 1; break; }
    if (!dirOk) return 0;
    for (i = 0; i < N_DROP_EXT; i++)
        if (pw_ends_with_i(p, DROP_EXTS[i])) return 1;
    return 0;
}

/* The process hooks report a full command line, not a bare path, so the
 * executable has to be extracted before any path rule can be applied to it.
 * Without this, "cmd.exe /c ..." has no basename match and a dropped binary
 * invoked with arguments never looks like it ends in ".exe". */
static void first_token(const char *cmd, char *out, int outsz)
{
    const char *p = cmd;
    int n = 0;
    if (!cmd || outsz <= 0) { if (outsz > 0) out[0] = 0; return; }
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && n < outsz - 1) out[n++] = *p++;
    } else {
        while (*p && *p != ' ' && *p != '\t' && n < outsz - 1) out[n++] = *p++;
    }
    out[n] = 0;
}

/* Does this event change something, as opposed to just looking at it? The
 * persistence and dropper rules below only make sense for writes - opening the
 * Startup folder to enumerate it is ordinary, copying a binary into it is not.
 * For CreateFile the answer is in the decoded access mask we put in `detail`. */
static int is_write_op(const PW_EVENT *ev)
{
    const char *api = ev->api;

    if (pw_contains_i(api, "Write") || pw_contains_i(api, "Delete") ||
        pw_contains_i(api, "Move") || pw_contains_i(api, "Copy") ||
        pw_contains_i(api, "SetValue") || pw_contains_i(api, "SetFileAttributes") ||
        pw_contains_i(api, "CreateKey") || pw_contains_i(api, "RemoveDirectory"))
        return 1;
    if (pw_contains_i(api, "CreateFile"))
        return pw_contains_i(ev->detail, "WRITE") ||
               pw_contains_i(ev->detail, "APPEND") ||
               pw_contains_i(ev->detail, "CREATE_ALWAYS");
    if (pw_contains_i(api, "Create")) return 1;
    return 0;
}

void pw_rules_apply(PW_EVENT *ev)
{
    const char *api = ev->api;
    const char *tgt = ev->target;
    int writing = is_write_op(ev);

    switch (ev->cat) {

    case PW_CAT_FILE:
        if (writing && pw_path_matches_any(tgt, PERSIST, N_PERSIST)) {
            mark(ev, L("写入自启动/持久化位置"));
            return;
        }
        if (pw_path_matches_any(tgt, SECRETS, N_SECRETS)) {
            /* A read counts here: reading a credential store is the behaviour
             * of interest, not just modifying it. */
            mark(ev, L("访问浏览器凭据/密码库/密钥文件"));
            return;
        }
        if (pw_contains_i(tgt, "\\drivers\\etc\\hosts") && writing) {
            mark(ev, L("修改 hosts 文件（可能劫持域名）"));
            return;
        }
        if (writing && is_drop_path(tgt)) {
            mark(ev, L("在可写目录落地可执行文件"));
            return;
        }
        if (writing && pw_contains_i(tgt, "\\windows\\system32\\") &&
            pw_contains_i(api, "CreateFile")) {
            note(ev, L("在 System32 下创建/写入文件"));
            return;
        }
        if (pw_contains_i(api, "Delete") && pw_contains_i(tgt, "\\windows\\")) {
            note(ev, L("删除系统目录下的文件"));
            return;
        }
        if (pw_contains_i(tgt, "\\shadow")) {
            mark(ev, L("疑似卷影副本操作（勒索软件常见手法）"));
            return;
        }
        break;

    case PW_CAT_REG:
        if (writing && pw_path_matches_any(tgt, PERSIST, N_PERSIST)) {
            mark(ev, L("写入注册表自启动/服务项"));
            return;
        }
        if (writing && (pw_contains_i(tgt, "\\windows defender") ||
                        pw_contains_i(tgt, "\\policies\\microsoft\\windows defender"))) {
            mark(ev, L("改动 Windows Defender 配置/排除项"));
            return;
        }
        if (writing && (pw_contains_i(tgt, "\\currentversion\\internet settings") ||
                        pw_contains_i(tgt, "\\currentversion\\winhttp") ||
                        pw_contains_i(ev->detail, "proxy"))) {
            note(ev, L("注册表代理设置被修改"));
            return;
        }
        break;

    case PW_CAT_NET:
        if (pw_contains_i(ev->detail, "SOCK_RAW")) {
            mark(ev, L("创建原始套接字（SOCK_RAW）"));
            return;
        }
        /* Outbound destinations are classified inside the connect hook, which
         * still has the original sockaddr; here we only pick up name lookups. */
        if (pw_streqi(api, "gethostbyname") || pw_streqi(api, "getaddrinfo") ||
            pw_streqi(api, "GetAddrInfoW") || pw_streqi(api, "DnsQuery_A")) {
            note(ev, L("域名解析"));
            return;
        }
        break;

    case PW_CAT_HTTP:
        if (pw_contains_i(tgt, "http://") && !pw_contains_i(tgt, "https://")) {
            note(ev, L("使用明文 HTTP 传输"));
            return;
        }
        if (pw_contains_i(api, "Proxy") || pw_contains_i(ev->detail, "proxy")) {
            note(ev, L("代理相关调用"));
            return;
        }
        if (pw_contains_i(ev->detail, "user-agent") &&
            (pw_contains_i(ev->detail, "curl") || pw_contains_i(ev->detail, "python") ||
             pw_contains_i(ev->detail, "wget") || pw_contains_i(ev->detail, "powershell"))) {
            note(ev, L("脚本类 User-Agent，疑似自动化下载"));
            return;
        }
        if (pw_contains_i(ev->detail, "content-type") &&
            pw_contains_i(ev->detail, "octet-stream")) {
            note(ev, L("下载二进制内容"));
            return;
        }
        break;

    case PW_CAT_PROC: {
        char exe[PW_TGT_LEN];
        const char *base;
        int i;

        first_token(tgt, exe, sizeof(exe));
        base = pw_base_name(exe);

        if (pw_contains_i(ev->detail, "-enc") || pw_contains_i(ev->detail, "encodedcommand") ||
            pw_contains_i(ev->detail, "-e ") || pw_contains_i(ev->detail, "frombase64string") ||
            pw_contains_i(ev->detail, "-w hidden") || pw_contains_i(ev->detail, "bypass")) {
            mark(ev, L("命令行包含编码/隐藏执行参数"));
            return;
        }
        for (i = 0; i < N_LOLBIN; i++) {
            if (pw_streqi(base, LOLBINS[i])) {
                note(ev, L("启动系统自带工具，可能是无文件落地执行"));
                return;
            }
        }
        if (is_drop_path(exe)) {
            mark(ev, L("从可写目录启动可执行文件"));
            return;
        }
        break;
    }

    case PW_CAT_MOD:
        if (is_drop_path(tgt)) {
            mark(ev, L("加载临时/用户目录下的 DLL"));
            return;
        }
        if (pw_contains_i(tgt, "appdata") && pw_ends_with_i(tgt, ".dll")) {
            note(ev, L("从用户目录加载模块"));
            return;
        }
        break;

    case PW_CAT_MEM:
        if (pw_contains_i(api, "VirtualProtect")) {
            /* A protect call is a transition, not an allocation: report which
             * way it went rather than reusing the allocation wording. */
            if (pw_contains_i(ev->detail, "-> PAGE_EXECUTE"))
                mark(ev, L("把已有内存改为可执行"));
            return;
        }
        if (pw_contains_i(ev->detail, "PAGE_EXECUTE_READWRITE")) {
            mark(ev, L("申请可写可执行内存（shellcode 注入常见手法）"));
            return;
        }
        if (pw_contains_i(api, "WriteProcessMemory")) {
            mark(ev, L("写入其它进程的内存"));
            return;
        }
        if (pw_contains_i(api, "CreateRemoteThread") ||
            pw_contains_i(api, "QueueUserAPC") ||
            pw_contains_i(api, "SetThreadContext")) {
            mark(ev, L("向其它进程注入代码"));
            return;
        }
        break;

    default:
        break;
    }
}
