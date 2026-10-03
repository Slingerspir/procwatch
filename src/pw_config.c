/* pw_config.c */
#include "pw_config.h"
#include "pw_lang.h"
#include "pw_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void pw_config_defaults(PW_CONFIG *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->gui         = 1;
    cfg->http        = 1;
    cfg->port        = 0;
    cfg->log_file    = 0;
    cfg->verbose     = 0;
    cfg->risk        = 1;
    cfg->previews    = 0;
    cfg->wininet     = 1;
    cfg->stack_trace = 1;
    cfg->lang        = PW_LANG_AUTO;
    cfg->ring        = 8192;
    cfg->disk_free_mb = 64;
    pw_data_dir(cfg->log_dir, sizeof(cfg->log_dir));
}

static int cfg_bool(const char *v)
{
    if (!v) return 1;
    if (pw_streqi(v, "0") || pw_streqi(v, "no") || pw_streqi(v, "off") ||
        pw_streqi(v, "false")) return 0;
    return 1;
}

/* Split "a=b,c=d" and apply each pair. Unknown keys are ignored so that an old
 * injector can drive a newer DLL without breaking it. */
void pw_config_parse(PW_CONFIG *cfg, const char *kv)
{
    char work[1024];
    char *p;

    if (!kv || !*kv) return;
    pw_str_copy(work, sizeof(work), kv);

    p = work;
    while (*p) {
        char *comma = strchr(p, ',');
        char *eq;
        char *key = p;
        char *val = NULL;

        if (comma) *comma = 0;
        /* allow ';' as an alternative separator */
        {
            char *semi = strchr(p, ';');
            if (semi) *semi = 0;
        }
        eq = strchr(p, '=');
        if (eq) { *eq = 0; val = eq + 1; }

        /* trim */
        while (*key == ' ' || *key == '\t') key++;
        {
            char *e = key + strlen(key);
            while (e > key && (e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
        }
        if (val) {
            while (*val == ' ' || *val == '\t') val++;
            {
                char *e = val + strlen(val);
                while (e > val && (e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
            }
        }

        if (pw_streqi(key, "gui"))           cfg->gui = cfg_bool(val);
        else if (pw_streqi(key, "http"))     cfg->http = cfg_bool(val);
        else if (pw_streqi(key, "port"))     cfg->port = val ? atoi(val) : 0;
        else if (pw_streqi(key, "log"))      cfg->log_file = cfg_bool(val);
        else if (pw_streqi(key, "logfile"))  cfg->log_file = cfg_bool(val);
        else if (pw_streqi(key, "verbose"))  cfg->verbose = cfg_bool(val);
        else if (pw_streqi(key, "risk"))     cfg->risk = cfg_bool(val);
        else if (pw_streqi(key, "previews")) cfg->previews = cfg_bool(val);
        else if (pw_streqi(key, "wininet"))  cfg->wininet = cfg_bool(val);
        else if (pw_streqi(key, "trace"))    cfg->stack_trace = cfg_bool(val);
        else if (pw_streqi(key, "lang"))     cfg->lang = pw_lang_parse(val);
        else if (pw_streqi(key, "ring"))     cfg->ring = val ? (unsigned)atoi(val) : cfg->ring;
        else if (pw_streqi(key, "logdir"))   pw_str_copy(cfg->log_dir, sizeof(cfg->log_dir), val ? val : "");

        if (!comma) break;
        p = comma + 1;
    }

    if (cfg->ring < 256)     cfg->ring = 256;
    if (cfg->ring > 262144)  cfg->ring = 262144;
    if (cfg->port < 0 || cfg->port > 65535) cfg->port = 0;
    if (cfg->log_dir[0] == 0) pw_data_dir(cfg->log_dir, sizeof(cfg->log_dir));
}

static void cfg_load_file(PW_CONFIG *cfg, const char *path, int oneShot)
{
    FILE *f = fopen(path, "rb");
    char line[1024];
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strpbrk(line, "\r\n");
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        if (nl) *nl = 0;
        if (line[0] == 0 || line[0] == '[') continue;
        /* Support both key=value and key=value,key=value on one line. */
        pw_config_parse(cfg, line);
    }
    fclose(f);
    if (oneShot) DeleteFileA(path);
}

/* Reading the options file must not itself be reported as target activity, so
 * callers run this with pw_suppress_enter(). */
void pw_config_load(PW_CONFIG *cfg)
{
    char dir[MAX_PATH], path[MAX_PATH];
    char env[1024];
    DWORD n;

    pw_config_defaults(cfg);

    pw_data_dir(dir, sizeof(dir));
    CreateDirectoryA(dir, NULL);

    pw_path_join(path, sizeof(path), dir, "config.ini");
    pw_str_copy(cfg->config_file, sizeof(cfg->config_file), path);
    cfg_load_file(cfg, path, 0);

    n = GetEnvironmentVariableA(PW_OPTS_ENV, env, sizeof(env));
    if (n > 0 && n < sizeof(env)) pw_config_parse(cfg, env);

    pw_path_join(path, sizeof(path), dir, PW_PENDING);
    cfg_load_file(cfg, path, 1);
}

void pw_config_to_string(const PW_CONFIG *cfg, char *out, int outsz)
{
    _snprintf(out, outsz,
              "gui=%d,http=%d,port=%d,log=%d,verbose=%d,risk=%d,previews=%d,"
              "wininet=%d,trace=%d,lang=%s,ring=%u",
              cfg->gui, cfg->http, cfg->port, cfg->log_file, cfg->verbose,
              cfg->risk, cfg->previews, cfg->wininet, cfg->stack_trace,
              cfg->lang == PW_LANG_ZH ? "zh" :
              cfg->lang == PW_LANG_EN ? "en" : "auto",
              cfg->ring);
    out[outsz - 1] = 0;
}

int pw_config_save_default(const PW_CONFIG *cfg)
{
    char dir[MAX_PATH], path[MAX_PATH];
    FILE *f;
    char s[512];

    pw_data_dir(dir, sizeof(dir));
    CreateDirectoryA(dir, NULL);
    pw_path_join(path, sizeof(path), dir, "config.ini");

    f = fopen(path, "wb");
    if (!f) return 0;
    fprintf(f, "# ProcWatch options - applied to every future injection\n");
    pw_config_to_string(cfg, s, sizeof(s));
    fprintf(f, "%s\n", s);
    fclose(f);
    return 1;
}

int pw_config_write_pending(const PW_CONFIG *cfg)
{
    char dir[MAX_PATH], path[MAX_PATH];
    FILE *f;
    char s[512];

    pw_data_dir(dir, sizeof(dir));
    CreateDirectoryA(dir, NULL);
    pw_path_join(path, sizeof(path), dir, PW_PENDING);

    f = fopen(path, "wb");
    if (!f) return 0;
    pw_config_to_string(cfg, s, sizeof(s));
    fprintf(f, "%s\n", s);
    fclose(f);
    return 1;
}
