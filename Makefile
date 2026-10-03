# ProcWatch - build file for MinGW-w64 (x86_64).
#
#   make            build everything into dist/
#   make dll        just the injectable monitor DLL
#   make clean
#
# Requires the MinGW-w64 gcc on PATH (this machine: /d/mingw64/bin).

CC      := gcc
SRCDIR  := src
DIST    := dist
BUILD   := build

WINVER  := -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00
CHARSET := -finput-charset=UTF-8 -fexec-charset=UTF-8
CFLAGS  := -O2 -Wall -Wextra -Wno-unused-parameter -std=gnu11 $(WINVER) $(CHARSET) -I$(SRCDIR) -I$(BUILD)/gen
# -static matters for distribution: without it MinGW links its own C runtime
# (mcfgthread or winpthread) as a separate DLL, which lives in the toolchain's
# bin directory and is not present on a machine that only downloaded the
# binaries. The result would be "libmcfgthread-2.dll is missing" for anyone who
# did not install the same toolchain.
LDFLAGS := -static

# ---------------------------------------------------------------- generated web

WEBUI_HDR := $(BUILD)/gen/pw_webui_html.h
HUB_HDR   := $(BUILD)/gen/pw_hub_html.h
EMBED     := $(BUILD)/embed.exe

# ---------------------------------------------------------------------- DLL

DLL_SRCS := \
	$(SRCDIR)/pw_util.c \
	$(SRCDIR)/pw_events.c \
	$(SRCDIR)/pw_config.c \
	$(SRCDIR)/pw_state.c \
	$(SRCDIR)/pw_rules.c \
	$(SRCDIR)/pw_json.c \
	$(SRCDIR)/pw_hooks.c \
	$(SRCDIR)/pw_hookapi.c \
	$(SRCDIR)/pw_hookapi_winhttp.c \
	$(SRCDIR)/pw_gui.c \
	$(SRCDIR)/pw_http.c \
	$(SRCDIR)/pw_dll.c

DLL_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILD)/%.o,$(DLL_SRCS))

DLL_LIBS := -lkernel32 -luser32 -ladvapi32 -lws2_32 -lwininet -lwinhttp \
            -lcomctl32 -lgdi32 -lshell32

# ------------------------------------------------------------------ injector

INJ_SRCS := $(SRCDIR)/injector.c $(SRCDIR)/pw_config.c $(SRCDIR)/pw_util.c
INJ_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILD)/inj_%.o,$(INJ_SRCS))
INJ_LIBS := -lkernel32 -luser32 -ladvapi32 -lws2_32

# ---------------------------------------------------------------- test target

TEST_SRCS := $(SRCDIR)/testtarget.c
TEST_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILD)/test_%.o,$(TEST_SRCS))
TEST_LIBS := -lkernel32 -luser32 -lws2_32 -lwinhttp -lwininet

# --------------------------------------------------------------------- rules

.PHONY: all dll injector testtarget web clean fixture

all: $(DIST)/ProcWatch.dll $(DIST)/injector.exe $(DIST)/testtarget.exe
	@echo ""
	@echo "  build complete - artifacts in $(DIST)/"
	@echo "    ProcWatch.dll    injectable monitor module (x64)"
	@echo "    injector.exe     injector / aggregation hub"
	@echo "    testtarget.exe   behaviour test target"
	@echo ""

dll: $(DIST)/ProcWatch.dll
injector: $(DIST)/injector.exe
testtarget: $(DIST)/testtarget.exe

web: $(WEBUI_HDR) $(HUB_HDR)

$(BUILD) $(DIST) $(BUILD)/gen:
	@mkdir -p $@

$(EMBED): tools/embed.c | $(BUILD)
	$(CC) -O2 -o $@ $<

$(WEBUI_HDR): web/webui.html $(EMBED) | $(BUILD)/gen
	$(EMBED) $< $@ pw_webui_html

$(HUB_HDR): web/hub.html $(EMBED) | $(BUILD)/gen
	$(EMBED) $< $@ pw_hub_html

# --- DLL objects (the two HTTP hook files also need the generated header) ---
$(BUILD)/%.o: $(SRCDIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/pw_http.o: $(WEBUI_HDR)

$(DIST)/ProcWatch.dll: $(DLL_OBJS) | $(DIST)
	$(CC) -shared -o $@ $(DLL_OBJS) $(DLL_LIBS) $(LDFLAGS)
	@echo "  [dll] $@"

# --- injector ---------------------------------------------------------------
$(BUILD)/inj_%.o: $(SRCDIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/inj_injector.o: $(HUB_HDR)

$(DIST)/injector.exe: $(INJ_OBJS) | $(DIST)
	$(CC) -o $@ $(INJ_OBJS) $(INJ_LIBS) $(LDFLAGS)
	@echo "  [exe] $@"

# --- test target ------------------------------------------------------------
$(BUILD)/test_%.o: $(SRCDIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(DIST)/testtarget.exe: $(TEST_OBJS) | $(DIST)
	$(CC) -o $@ $(TEST_OBJS) $(TEST_LIBS) $(LDFLAGS)
	@echo "  [exe] $@"

# --- elevation test fixture -------------------------------------------------
# A throwaway program whose manifest requires administrator rights, so the
# injector's ERROR_ELEVATION_REQUIRED handling can be exercised without aiming
# it at some real elevated program on the machine.
#
#   make fixture
#   injector.exe --exe build\elevation_fixture.exe --no-elevate
#
fixture: | $(BUILD)
	windres tools/elevation_fixture.rc -O coff -o $(BUILD)/elevation_fixture.res
	$(CC) -O2 -o $(BUILD)/elevation_fixture.exe tools/elevation_fixture.c \
		$(BUILD)/elevation_fixture.res
	@echo "  [fixture] $(BUILD)/elevation_fixture.exe"

clean:
	rm -rf $(BUILD) $(DIST)
