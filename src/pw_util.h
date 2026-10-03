/* pw_util.h - small helpers shared by every ProcWatch module. */
#ifndef PW_UTIL_H
#define PW_UTIL_H

#include "pw_common.h"

unsigned long long pw_now_ms(void);
void  pw_ts_str(unsigned long long unix_ms, char *out, int outsz);   /* HH:MM:SS.mmm */
void  pw_iso_str(unsigned long long unix_ms, char *out, int outsz);

int   pw_streq(const char *a, const char *b);
int   pw_streqi(const char *a, const char *b);
int   pw_ends_with_i(const char *s, const char *suffix);
int   pw_contains_i(const char *hay, const char *needle);

const char *pw_base_name(const char *path);
void  pw_str_copy(char *dst, int dstsz, const char *src);
void  pw_str_cat(char *dst, int dstsz, const char *src);

void  pw_wide_to_utf8(const wchar_t *w, char *out, int outsz);
void  pw_utf8_to_wide(const char *s, wchar_t *out, int outsz);
/* ANSI (system code page) to UTF-8. The A-suffixed APIs hand us strings in the
 * active code page, which on this machine is not UTF-8. */
void  pw_ansi_to_utf8(const char *s, char *out, int outsz);

int   pw_is_printable(const unsigned char *p, int n);
void  pw_hex_ascii(const unsigned char *p, int n, char *out, int outsz);
void  pw_json_escape(const char *in, char *out, int outsz);
void  pw_csv_field(const char *in, char *out, int outsz);

void  pw_format_sockaddr(const struct sockaddr *sa, int salen, char *out, int outsz);
int   pw_sockaddr_is_local(const struct sockaddr *sa);

void  pw_dir_create_for_file(const char *file);
void  pw_get_temp_dir(char *out, int outsz);
void  pw_data_dir(char *out, int outsz);            /* %TEMP%\ProcWatch */
void  pw_path_join(char *out, int outsz, const char *a, const char *b);

/* Path rule helpers used by the risk engine. */
int   pw_path_matches_any(const char *path, const char *const *pats, int npat);

/* One event as a single line of JSON (no trailing newline). Returns the number
 * of bytes written excluding the terminator, or -1 if it did not fit. */
int   pw_event_json(const PW_EVENT *e, unsigned long pid, char *out, int outsz);

#endif /* PW_UTIL_H */
