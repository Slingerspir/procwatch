/* pw_lang.c - the string lookup behind L(...).
 *
 * The table is generated (build/gen/pw_lang_table.h) from tools/lang_en.txt and
 * compiled in, so there is no file to find at run time and nothing to fail on a
 * machine where the DLL is injected into someone else's process.
 *
 * Lookups are hashed: a hook reports events constantly and a linear scan over
 * several hundred strings on every one of them would be the wrong shape. In
 * Chinese mode pw_tr returns immediately, so the whole mechanism costs a single
 * predictable branch. */
#include "pw_lang.h"
#include <string.h>

typedef struct {
    const char *zh;
    const char *en;
} PW_LANG_PAIR;

#include "pw_lang_table.h"

#define INDEX_SIZE 2048               /* power of two, comfortably > entry count */

static PW_LANG_PAIR g_index[INDEX_SIZE];
static int          g_english = 0;
static int          g_index_ready = 0;

static unsigned int hash_string(const char *s)
{
    /* FNV-1a over the bytes; the keys are UTF-8 so this is stable. */
    unsigned int h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

static void build_index(void)
{
    int i;
    memset(g_index, 0, sizeof(g_index));
    for (i = 0; i < PW_LANG_PAIR_COUNT; i++) {
        unsigned int slot = hash_string(pw_lang_pairs[i].zh) & (INDEX_SIZE - 1);
        while (g_index[slot].zh) slot = (slot + 1) & (INDEX_SIZE - 1);
        g_index[slot] = pw_lang_pairs[i];
    }
    g_index_ready = 1;
}

int pw_lang_parse(const char *value)
{
    if (!value || !*value) return PW_LANG_AUTO;
    if (!_strnicmp(value, "zh", 2)) return PW_LANG_ZH;   /* zh, zh-CN, ... */
    if (!_strnicmp(value, "en", 2)) return PW_LANG_EN;   /* en, en-US, ... */
    return PW_LANG_AUTO;
}

static int detect_system_language(void)
{
    /* A machine whose UI is Chinese gets Chinese; everything else gets English,
     * which is the safer default for a tool that may be run by anyone. */
    return (PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE)
             ? PW_LANG_ZH : PW_LANG_EN;
}

void pw_lang_init(int configured)
{
    int lang = configured;

    if (lang == PW_LANG_AUTO) lang = detect_system_language();
    g_english = (lang == PW_LANG_EN);
    if (g_english && !g_index_ready) build_index();
}

int pw_lang_get(void) { return g_english ? PW_LANG_EN : PW_LANG_ZH; }
int pw_lang_is_en(void) { return g_english; }

const char *pw_tr(const char *zh)
{
    unsigned int slot;

    if (!g_english || !zh) return zh;      /* Chinese mode: nothing to do */
    if (!g_index_ready) build_index();

    slot = hash_string(zh) & (INDEX_SIZE - 1);
    while (g_index[slot].zh) {
        if (strcmp(g_index[slot].zh, zh) == 0) return g_index[slot].en;
        slot = (slot + 1) & (INDEX_SIZE - 1);
    }
    return zh;                             /* untranslated: show the original */
}
