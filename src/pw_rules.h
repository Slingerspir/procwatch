/* pw_rules.h - heuristic risk classification applied to every event. */
#ifndef PW_RULES_H
#define PW_RULES_H

#include "pw_common.h"

/* May raise ev->lvl and annotate ev->detail with the matched rule. */
void pw_rules_apply(PW_EVENT *ev);

#endif /* PW_RULES_H */
