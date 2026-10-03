/* pw_json.c - one event rendered as a single line of JSON.
 *
 * Separate from pw_util.c on purpose: this needs the category and level name
 * tables that live with the process state, and keeping it out of pw_util.c lets
 * the injector link pw_util without dragging in the whole monitoring stack. */
#include "pw_common.h"
#include "pw_state.h"
#include "pw_util.h"
#include <stdio.h>

int pw_event_json(const PW_EVENT *e, unsigned long pid, char *out, int outsz)
{
    char ts[40], api[200], tgt[1600], det[1400];
    int n;

    if (!e || !out || outsz < 256) return -1;

    pw_iso_str(e->ts, ts, sizeof(ts));
    pw_json_escape(e->api, api, sizeof(api));
    pw_json_escape(e->target, tgt, sizeof(tgt));
    pw_json_escape(e->detail, det, sizeof(det));

    n = snprintf(out, (size_t)outsz,
                 "{\"seq\":%llu,\"ts\":%llu,\"time\":\"%s\",\"pid\":%lu,\"tid\":%u,"
                 "\"cat\":%u,\"catName\":\"%s\",\"lvl\":%u,\"lvlName\":\"%s\","
                 "\"api\":\"%s\",\"size\":%u,\"result\":%d,\"target\":\"%s\","
                 "\"detail\":\"%s\"}",
                 e->seq, e->ts, ts, pid, e->tid,
                 e->cat, pw_cat_name(e->cat), e->lvl, pw_lvl_name(e->lvl),
                 api, e->size, e->result, tgt, det);
    if (n < 0 || n >= outsz) return -1;
    return n;
}
