/* pw_gui.h - the in-process monitoring window. */
#ifndef PW_GUI_H
#define PW_GUI_H

#include "pw_common.h"

/* Create the window on its own thread (with its own message loop, so it works
 * inside console programs and services too). Returns 1 if the window came up,
 * 0 if the host process cannot show one - the WebUI still works either way. */
int  pw_gui_start(void);
void pw_gui_stop(void);
int  pw_gui_running(void);

/* Export the rows currently held in the window. Returns 1 on success and fills
 * `outPath` with the file that was written. */
int  pw_gui_export(char *outPath, int outsz, int csv);

/* Ask the window to rebuild its rows (used when a filter changes remotely). */
void pw_gui_refresh(void);

#endif /* PW_GUI_H */
