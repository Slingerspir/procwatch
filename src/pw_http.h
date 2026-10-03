/* pw_http.h - the WebUI server embedded in the injected DLL. */
#ifndef PW_HTTP_H
#define PW_HTTP_H

#include "pw_common.h"

/* Bind the first free port at or above PW_PORT_BASE (or the configured one) and
 * start serving. Returns the port, or 0 if the server could not start. */
int  pw_http_start(void);
void pw_http_stop(void);
int  pw_http_port(void);

/* Write "%TEMP%\ProcWatch\<pid>.json" so the hub can find this instance. */
void pw_http_write_discovery(void);

#endif /* PW_HTTP_H */
