/* pw_events.h - lock-protected ring buffer of observed events.
 *
 * The ring is written from inside API hooks, so appending must never allocate,
 * never call a hooked API and never block for long. Everything else (disk
 * mirroring, HTTP serving, GUI refresh) pulls snapshots out by sequence number.
 */
#ifndef PW_EVENTS_H
#define PW_EVENTS_H

#include "pw_common.h"

typedef struct {
    PW_EVENT      *buf;
    unsigned int   cap;
    unsigned long long written;    /* total events ever appended; oldest seq = written-cap+1 */
    unsigned long long cleared_to; /* readers ignore everything at or below this seq */
    CRITICAL_SECTION cs;
    int            ready;
} PW_LOG;

/* Number of events dropped because a reader never consumed them in time. */
extern volatile long long g_pw_dropped;

int  pw_log_init(PW_LOG *log, unsigned int capacity);
void pw_log_free(PW_LOG *log);
void pw_log_clear(PW_LOG *log);

/* Append one event. Returns the assigned sequence number (0 on failure).
 * The caller fills seq/ts/tid itself is NOT required - this fills them in. */
unsigned long long pw_log_append(PW_LOG *log, const PW_EVENT *ev);

/* Copy up to maxOut events with seq > afterSeq, in ascending order.
 * Returns the number copied; *outLast receives the newest seq available. */
unsigned int pw_log_since(PW_LOG *log, unsigned long long afterSeq,
                          PW_EVENT *out, unsigned int maxOut,
                          unsigned long long *outLast);

unsigned long long pw_log_last_seq(PW_LOG *log);
unsigned long long pw_log_count(PW_LOG *log);    /* events currently retained */
void pw_log_stats(PW_LOG *log, unsigned long long *total,
                  unsigned int *counts, int ncat, unsigned int *lvls, int nlvl);

#endif /* PW_EVENTS_H */
