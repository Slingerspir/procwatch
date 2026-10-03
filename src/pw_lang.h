/* pw_lang.h - language selection for everything the user reads.
 *
 * User-visible literals in the sources are wrapped in L(...):
 *
 *     fmt(det, sizeof(det), L("读取 %u 字节"), n);
 *
 * The Chinese text itself is the lookup key rather than an identifier. That has
 * two consequences worth the small runtime cost:
 *
 *   - the transformation of the sources is mechanical. A literal is either
 *     wrapped or it is not; there is no enum to keep in sync with a call site.
 *   - a missing translation degrades to the original Chinese. It cannot produce
 *     blank text, a wrong argument order or a crash.
 *
 * Wide literals in the GUI are converted to W("...") instead, which translates
 * and then widens. tools/lang_en.txt holds the translations and
 * tools/gen_lang.py compiles them into build/gen/pw_lang_table.h. */
#ifndef PW_LANG_H
#define PW_LANG_H

#include "pw_common.h"

#define L(s) pw_tr(s)

/* PW_LANG_AUTO / PW_LANG_ZH / PW_LANG_EN are declared in pw_common.h. */

/* Select the language and build the lookup index. Safe to call more than once;
 * call it before anything reports a string. */
void pw_lang_init(int configured);

int pw_lang_get(void);          /* PW_LANG_ZH or PW_LANG_EN, resolved */
int pw_lang_is_en(void);

/* Translate one literal. Returns `zh` unchanged in Chinese mode, and also when
 * the string has no translation. */
const char *pw_tr(const char *zh);

/* Parse "auto" / "zh" / "en" (also accepting zh-CN, en-US, ...). */
int pw_lang_parse(const char *value);

#endif /* PW_LANG_H */
