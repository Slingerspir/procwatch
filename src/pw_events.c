/* pw_events.c */
#include "pw_events.h"
#include "pw_util.h"
#include <stdlib.h>
#include <string.h>

volatile long long g_pw_dropped = 0;

int pw_log_init(PW_LOG *log, unsigned int capacity)
{
    if (!log || capacity < 64) return 0;
    memset(log, 0, sizeof(*log));
    log->buf = (PW_EVENT *)calloc(capacity, sizeof(PW_EVENT));
    if (!log->buf) return 0;
    log->cap = capacity;
    log->written = 0;
    log->cleared_to = 0;
    InitializeCriticalSection(&log->cs);
    log->ready = 1;
    return 1;
}

void pw_log_free(PW_LOG *log)
{
    if (!log || !log->ready) return;
    EnterCriticalSection(&log->cs);
    free(log->buf);
    log->buf = NULL;
    log->ready = 0;
    LeaveCriticalSection(&log->cs);
    DeleteCriticalSection(&log->cs);
}

/* Clearing must not reset the sequence counter: an already-connected WebUI or
 * GUI holds a cursor. Instead we remember how far the log was cleared and make
 * every reader jump past it. */
void pw_log_clear(PW_LOG *log)
{
    if (!log || !log->ready) return;
    EnterCriticalSection(&log->cs);
    log->cleared_to = log->written;
    LeaveCriticalSection(&log->cs);
}

unsigned long long pw_log_append(PW_LOG *log, const PW_EVENT *ev)
{
    unsigned long long seq;
    unsigned int idx;

    if (!log || !log->ready || !ev) return 0;

    EnterCriticalSection(&log->cs);
    log->written++;
    seq = log->written;
    idx = (unsigned int)((seq - 1) % log->cap);
    log->buf[idx] = *ev;
    log->buf[idx].seq = seq;
    if (log->buf[idx].ts == 0) log->buf[idx].ts = pw_now_ms();
    if (log->buf[idx].tid == 0) log->buf[idx].tid = GetCurrentThreadId();
    LeaveCriticalSection(&log->cs);
    return seq;
}

unsigned int pw_log_since(PW_LOG *log, unsigned long long afterSeq,
                          PW_EVENT *out, unsigned int maxOut,
                          unsigned long long *outLast)
{
    unsigned int n = 0;
    unsigned long long last, first, cur;

    if (outLast) *outLast = 0;
    if (!log || !log->ready || !out || maxOut == 0) return 0;

    EnterCriticalSection(&log->cs);
    last = log->written;
    if (outLast) *outLast = last;
    if (last == 0) { LeaveCriticalSection(&log->cs); return 0; }

    first = (last > log->cap) ? (last - log->cap + 1) : 1;
    if (first < log->cleared_to + 1) first = log->cleared_to + 1;

    cur = afterSeq + 1;
    if (cur < first) {
        g_pw_dropped += (long long)(first - cur);
        cur = first;
    }
    for (; cur <= last && n < maxOut; cur++) {
        unsigned int idx = (unsigned int)((cur - 1) % log->cap);
        PW_EVENT *slot = &log->buf[idx];
        /* A slot whose seq does not match the one requested was recycled by a
         * faster writer while this reader lagged - skip it, do not misreport. */
        if (slot->seq != cur) continue;
        out[n++] = *slot;
    }
    LeaveCriticalSection(&log->cs);
    return n;
}

unsigned long long pw_log_last_seq(PW_LOG *log)
{
    unsigned long long v;
    if (!log || !log->ready) return 0;
    EnterCriticalSection(&log->cs);
    v = log->written;
    LeaveCriticalSection(&log->cs);
    return v;
}

unsigned long long pw_log_count(PW_LOG *log)
{
    unsigned long long v, first;
    if (!log || !log->ready) return 0;
    EnterCriticalSection(&log->cs);
    v = log->written;
    first = (v > log->cap) ? (v - log->cap + 1) : 1;
    if (first < log->cleared_to + 1) first = log->cleared_to + 1;
    v = (v >= first) ? (v - first + 1) : 0;
    LeaveCriticalSection(&log->cs);
    return v;
}

void pw_log_stats(PW_LOG *log, unsigned long long *total,
                  unsigned int *counts, int ncat, unsigned int *lvls, int nlvl)
{
    unsigned long long last, first, cur;
    int i;

    if (total) *total = 0;
    for (i = 0; i < ncat; i++) counts[i] = 0;
    for (i = 0; i < nlvl; i++) lvls[i] = 0;
    if (!log || !log->ready) return;

    EnterCriticalSection(&log->cs);
    last = log->written;
    if (total) *total = last;
    first = (last > log->cap) ? (last - log->cap + 1) : 1;
    if (first < log->cleared_to + 1) first = log->cleared_to + 1;
    for (cur = first; cur <= last; cur++) {
        unsigned int idx = (unsigned int)((cur - 1) % log->cap);
        const PW_EVENT *e = &log->buf[idx];
        if (e->seq != cur) continue;
        if (e->cat < (unsigned char)ncat) counts[e->cat]++;
        if (e->lvl < (unsigned char)nlvl) lvls[e->lvl]++;
    }
    LeaveCriticalSection(&log->cs);
}
