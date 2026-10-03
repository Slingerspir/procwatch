/* pw_gui.c - the monitoring window that appears inside the injected process.
 *
 * The list is a virtual ListView (LVS_OWNERDATA): the control never owns the
 * rows, it asks us for the text of whichever lines are on screen. That keeps a
 * 10k row log scrolling at full speed, and it means filtering is just "change
 * what row N means" followed by a redraw.
 *
 * The window runs on its own thread with its own message loop, so this works in
 * processes that have no UI of their own (console programs, services with a
 * desktop). If the window cannot be created we degrade to the WebUI. */
#include "pw_gui.h"
#include "pw_state.h"
#include "pw_events.h"
#include "pw_util.h"
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ID_LIST          1001
#define ID_BTN_PAUSE     1002
#define ID_BTN_CLEAR     1003
#define ID_BTN_WEB       1004
#define ID_BTN_EXPORT    1005
#define ID_CMB_CAT       1006
#define ID_CHK_SUSPECT   1007
#define ID_EDIT_SEARCH   1008
#define ID_BTN_COPY      1009
#define ID_STATUS        1010
#define ID_TIMER         1

#define VIEW_CAP         4000
#define PULL_CHUNK       256
#define MAX_PULL_ROUNDS  48

typedef struct {
    PW_EVENT        *rows;
    unsigned int     count;
} View;

typedef struct {
    HWND         hwnd;
    HWND         list;
    HWND         btnPause, btnClear, btnWeb, btnExport, btnCopy;
    HWND         cmbCat, chkSuspect, editSearch, status;
    HFONT        font;
    View         view;
    PW_EVENT    *pull;
    unsigned long long lastSeq;
    int          catFilter;      /* 0 = all */
    int          onlySuspect;
    wchar_t      search[128];
    int          autoScroll;
    int          alive;
} GuiState;

static GuiState       g_gui;
static HANDLE         g_thread = NULL;
static HANDLE         g_ready = NULL;
static volatile long  g_stop = 0;

/* ------------------------------------------------------------- view helpers */

static void view_free(GuiState *g)
{
    free(g->view.rows);
    g->view.rows = NULL;
    g->view.count = 0;
}

static void view_push(GuiState *g, const PW_EVENT *ev)
{
    if (g->view.count >= VIEW_CAP) {
        /* Drop the older half in one move instead of shifting per event. */
        unsigned int keep = VIEW_CAP / 2;
        memmove(g->view.rows, g->view.rows + (VIEW_CAP - keep),
                (size_t)keep * sizeof(PW_EVENT));
        g->view.count = keep;
    }
    g->view.rows[g->view.count++] = *ev;
}

static int row_matches(GuiState *g, const PW_EVENT *ev)
{
    if (g->catFilter && ev->cat != g->catFilter) return 0;
    if (g->onlySuspect && ev->lvl != PW_LVL_SUSPECT) return 0;
    if (g->search[0]) {
        char needle[256];
        pw_wide_to_utf8(g->search, needle, sizeof(needle));
        if (!pw_contains_i(ev->target, needle) &&
            !pw_contains_i(ev->detail, needle) &&
            !pw_contains_i(ev->api, needle) &&
            !pw_contains_i(pw_cat_name(ev->cat), needle))
            return 0;
    }
    return 1;
}

/* Drain everything new from the ring into the view. */
static void pull_new(GuiState *g)
{
    int rounds = 0;
    unsigned int n, i;

    while (rounds++ < MAX_PULL_ROUNDS) {
        unsigned long long last = g->lastSeq;
        n = pw_log_since(&g_log, last, g->pull, PULL_CHUNK, &last);
        if (n == 0) break;
        for (i = 0; i < n; i++)
            if (row_matches(g, &g->pull[i])) view_push(g, &g->pull[i]);
        g->lastSeq = g->pull[n - 1].seq;
    }
    {
        unsigned long long globalLast = pw_log_last_seq(&g_log);
        if (globalLast > g->lastSeq) g->lastSeq = globalLast;
    }
}

/* Throw the view away and replay everything still resident in the ring. */
static void rebuild_view(GuiState *g)
{
    unsigned long long cursor = 0, last = 0;
    int rounds = 0;

    g->view.count = 0;
    for (;;) {
        unsigned int n, i;
        if (++rounds > 512) break;
        n = pw_log_since(&g_log, cursor, g->pull, PULL_CHUNK, &last);
        if (n == 0) break;
        for (i = 0; i < n; i++)
            if (row_matches(g, &g->pull[i])) view_push(g, &g->pull[i]);
        cursor = g->pull[n - 1].seq;
        if (cursor >= last) break;
    }
    g->lastSeq = last;
}

/* --------------------------------------------------------------- rendering */

static const wchar_t *COL_TITLE[6] = { L"时间", L"类别", L"级别", L"API", L"目标 / 路径", L"详情" };
static int COL_WIDTH[6] = { 96, 62, 62, 132, 420, 460 };

static wchar_t g_cell[6][768];

static void fill_cell(GuiState *g, int col, const PW_EVENT *ev)
{
    wchar_t *out = g_cell[col];
    char tmp[800];
    out[0] = 0;

    switch (col) {
    case 0: pw_ts_str(ev->ts, tmp, sizeof(tmp)); break;
    case 1: pw_str_copy(tmp, sizeof(tmp), pw_cat_name(ev->cat)); break;
    case 2: pw_str_copy(tmp, sizeof(tmp), pw_lvl_name(ev->lvl)); break;
    case 3: pw_str_copy(tmp, sizeof(tmp), ev->api); break;
    case 4: pw_str_copy(tmp, sizeof(tmp), ev->target); break;
    case 5: pw_str_copy(tmp, sizeof(tmp), ev->detail); break;
    default: tmp[0] = 0; break;
    }
    pw_utf8_to_wide(tmp, out, 768);
    (void)g;
}

static void refresh_status(GuiState *g)
{
    unsigned long long total = pw_log_last_seq(&g_log);
    unsigned int counts[9];
    unsigned int lvls[4];
    wchar_t w[400];
    char buf[400];
    int shown = (int)g->view.count;

    pw_log_stats(&g_log, &total, counts, 9, lvls, 4);
    if (g_cfg.http && g_http_url[0]) {
        _snprintf(buf, sizeof(buf),
                  "  累计 %llu 条  |  缓存 %u 条  |  显示 %d 条  |  可疑 %u 条  |  "
                  "WebUI: http://%s  |  丢失 %lld",
                  total, (unsigned)pw_log_count(&g_log), shown,
                  lvls[PW_LVL_SUSPECT], g_http_url, g_pw_dropped);
    } else {
        _snprintf(buf, sizeof(buf),
                  "  累计 %llu 条  |  缓存 %u 条  |  显示 %d 条  |  可疑 %u 条  |  "
                  "WebUI 未启用  |  丢失 %lld",
                  total, (unsigned)pw_log_count(&g_log), shown,
                  lvls[PW_LVL_SUSPECT], g_pw_dropped);
    }
    buf[sizeof(buf) - 1] = 0;
    pw_utf8_to_wide(buf, w, 400);
    SetWindowTextW(g->status, w);
}

static void refresh_list(GuiState *g)
{
    int top, perPage;
    unsigned int count;

    if (!g->list) return;
    top = (int)SendMessageW(g->list, LVM_GETTOPINDEX, 0, 0);
    perPage = (int)SendMessageW(g->list, LVM_GETCOUNTPERPAGE, 0, 0);
    count = g->view.count;

    /* Only follow the tail while the operator is already looking at the tail. */
    if (g->autoScroll || top + perPage >= (int)count - 1) {
        g->autoScroll = 1;
    }

    SendMessageW(g->list, LVM_SETITEMCOUNT, (WPARAM)count, LVSICF_NOSCROLL);
    if (g->autoScroll && count)
        SendMessageW(g->list, LVM_ENSUREVISIBLE, (WPARAM)(count - 1), FALSE);
    InvalidateRect(g->list, NULL, FALSE);
    refresh_status(g);
}

/* ------------------------------------------------------------------ export */

static int export_rows(GuiState *g, char *outPath, int outsz, int csv)
{
    char dir[MAX_PATH], path[MAX_PATH];
    unsigned long long now = pw_now_ms();
    FILE *f;
    unsigned int i;

    if (!g->view.count) return 0;
    pw_data_dir(dir, sizeof(dir));
    CreateDirectoryA(dir, NULL);
    _snprintf(path, sizeof(path), "%s\\events-%lu-%llu.%s", dir,
              (unsigned long)g_pid, now, csv ? "csv" : "jsonl");
    path[sizeof(path) - 1] = 0;

    f = fopen(path, "wb");
    if (!f) return 0;

    if (csv) {
        fprintf(f, "\xEF\xBB\xBF");    /* BOM so Excel reads the UTF-8 correctly */
        fprintf(f, "\"time\",\"pid\",\"tid\",\"category\",\"level\",\"api\",\"target\",\"detail\"\n");
    }
    for (i = 0; i < g->view.count; i++) {
        const PW_EVENT *e = &g->view.rows[i];
        char ts[40], tgt[1600], det[1400], api[160], cat[128], lvl[128];
        pw_iso_str(e->ts, ts, sizeof(ts));
        if (csv) {
            pw_csv_field(ts, api, sizeof(api));
            fprintf(f, "%s,", api);
            fprintf(f, "%lu,%u,", (unsigned long)g_pid, e->tid);
            pw_csv_field(pw_cat_name(e->cat), cat, sizeof(cat));
            fprintf(f, "%s,", cat);
            pw_csv_field(pw_lvl_name(e->lvl), lvl, sizeof(lvl));
            fprintf(f, "%s,", lvl);
            pw_csv_field(e->api, api, sizeof(api));
            fprintf(f, "%s,", api);
            pw_csv_field(e->target, tgt, sizeof(tgt));
            fprintf(f, "%s,", tgt);
            pw_csv_field(e->detail, det, sizeof(det));
            fprintf(f, "%s\n", det);
        } else {
            char line[4096];
            int n = pw_event_json(e, (unsigned long)g_pid, line, sizeof(line));
            if (n > 0) fprintf(f, "%s\n", line);
        }
    }
    fclose(f);
    pw_str_copy(outPath, outsz, path);
    return 1;
}

static void copy_visible(GuiState *g, int selectedOnly)
{
    size_t cap = 256 * 1024;
    char *buf = (char *)malloc(cap);
    size_t used = 0;
    unsigned int i;
    HGLOBAL mem;
    char *dst;

    if (!buf) return;
    buf[0] = 0;

    if (selectedOnly) {
        int sel = (int)SendMessageW(g->list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
        if (sel >= 0 && (unsigned int)sel < g->view.count) {
            const PW_EVENT *e = &g->view.rows[sel];
            char ts[40];
            pw_ts_str(e->ts, ts, sizeof(ts));
            used += (size_t)snprintf(buf + used, cap - used,
                                     "%s  %s  %s  %s  %s  %s\r\n", ts,
                                     pw_cat_name(e->cat), pw_lvl_name(e->lvl),
                                     e->api, e->target, e->detail);
        }
    } else {
        for (i = 0; i < g->view.count && used + 1600 < cap; i++) {
            const PW_EVENT *e = &g->view.rows[i];
            char ts[40];
            pw_ts_str(e->ts, ts, sizeof(ts));
            used += (size_t)snprintf(buf + used, cap - used,
                                     "%s  %s  %s  %s  %s  %s\r\n", ts,
                                     pw_cat_name(e->cat), pw_lvl_name(e->lvl),
                                     e->api, e->target, e->detail);
        }
    }

    if (used && OpenClipboard(g->hwnd)) {
        EmptyClipboard();
        mem = GlobalAlloc(GMEM_MOVEABLE, used + 1);
        if (mem) {
            dst = (char *)GlobalLock(mem);
            if (dst) {
                memcpy(dst, buf, used + 1);
                GlobalUnlock(mem);
                SetClipboardData(CF_TEXT, mem);
            }
        }
        CloseClipboard();
    }
    free(buf);
}

/* --------------------------------------------------------------- window proc */

static void layout(GuiState *g, int w, int h)
{
    int y = 6, bh = 26, pad = 6;
    int x = pad;

    MoveWindow(g->btnPause, x, y, 76, bh, TRUE); x += 80;
    MoveWindow(g->btnClear, x, y, 68, bh, TRUE); x += 72;
    MoveWindow(g->btnExport, x, y, 82, bh, TRUE); x += 86;
    MoveWindow(g->btnCopy, x, y, 82, bh, TRUE); x += 86;
    MoveWindow(g->btnWeb, x, y, 104, bh, TRUE); x += 112;
    MoveWindow(g->cmbCat, x, y, 104, 200, TRUE); x += 110;
    MoveWindow(g->chkSuspect, x, y, 90, bh, TRUE); x += 96;
    MoveWindow(g->editSearch, x, y, w - x - pad, bh, TRUE);

    MoveWindow(g->list, 0, y + bh + 6, w, h - (y + bh + 6) - 24, TRUE);
    MoveWindow(g->status, 0, h - 22, w, 22, TRUE);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    GuiState *g = &g_gui;

    switch (msg) {
    case WM_SIZE:
        layout(g, LOWORD(lp), HIWORD(lp));
        return 0;

    case WM_TIMER:
        if (wp == ID_TIMER) {
            unsigned long long before = g->lastSeq;
            pull_new(g);
            if (g->view.count || g->lastSeq != before) refresh_list(g);
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_BTN_PAUSE:
            if (g_paused) {
                g_paused = 0;
                SetWindowTextW(g->btnPause, L"暂停");
            } else {
                g_paused = 1;
                SetWindowTextW(g->btnPause, L"继续");
            }
            return 0;

        case ID_BTN_CLEAR:
            pw_log_clear(&g_log);
            g->view.count = 0;
            g->lastSeq = pw_log_last_seq(&g_log);
            refresh_list(g);
            return 0;

        case ID_BTN_EXPORT:
            {
                char path[MAX_PATH];
                wchar_t wpath[MAX_PATH * 2], info[MAX_PATH * 3];
                if (export_rows(g, path, sizeof(path), 0)) {
                    pw_utf8_to_wide(path, wpath, MAX_PATH * 2);
                    _snwprintf(info, MAX_PATH * 3, L"已导出 %u 条记录到：\n%s",
                               g->view.count, wpath);
                    info[MAX_PATH * 3 - 1] = 0;
                    MessageBoxW(hwnd, info, L"ProcWatch 导出", MB_OK | MB_ICONINFORMATION);
                } else {
                    MessageBoxW(hwnd, L"没有可导出的记录。", L"ProcWatch",
                                MB_OK | MB_ICONWARNING);
                }
            }
            return 0;

        case ID_BTN_COPY:
            copy_visible(g, 0);
            return 0;

        case ID_BTN_WEB:
            if (g_http_url[0]) {
                wchar_t url[128];
                char u[128];
                _snprintf(u, sizeof(u), "http://%s/", g_http_url);
                u[sizeof(u) - 1] = 0;
                pw_utf8_to_wide(u, url, 128);
                ShellExecuteW(NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
            } else {
                MessageBoxW(hwnd, L"WebUI 未启用（http=0）。", L"ProcWatch",
                            MB_OK | MB_ICONINFORMATION);
            }
            return 0;

        case ID_CMB_CAT:
            if (HIWORD(wp) == CBN_SELCHANGE) {
                int sel = (int)SendMessageW(g->cmbCat, CB_GETCURSEL, 0, 0);
                g->catFilter = (sel <= 0) ? 0 : sel;   /* index N == category N */
                rebuild_view(g);
                refresh_list(g);
            }
            return 0;

        case ID_CHK_SUSPECT:
            g->onlySuspect =
                (SendMessageW(g->chkSuspect, BM_GETCHECK, 0, 0) == BST_CHECKED);
            rebuild_view(g);
            refresh_list(g);
            return 0;

        case ID_EDIT_SEARCH:
            if (HIWORD(wp) == EN_CHANGE) {
                GetWindowTextW(g->editSearch, g->search, 128);
                /* Replaying the whole ring on every keystroke would be wasteful;
                 * the search box is re-applied on Enter or on the next tick. */
            }
            return 0;
        }
        break;

    case WM_NOTIFY:
        {
            NMHDR *nh = (NMHDR *)lp;
            if (nh->idFrom == ID_LIST) {
                if (nh->code == LVN_GETDISPINFOW) {
                    NMLVDISPINFOW *di = (NMLVDISPINFOW *)lp;
                    int row = di->item.iItem;
                    int col = di->item.iSubItem;
                    if (row < 0 || (unsigned int)row >= g->view.count) {
                        di->item.pszText = L"";
                        return 0;
                    }
                    if (col < 0 || col > 5) col = 0;
                    if (di->item.mask & LVIF_TEXT) {
                        fill_cell(g, col, &g->view.rows[row]);
                        di->item.pszText = g_cell[col];
                    }
                    return 0;
                }
                if (nh->code == NM_CUSTOMDRAW) {
                    /* Colour by level: red for rule hits, amber for noteworthy. */
                    NMLVCUSTOMDRAW *cd = (NMLVCUSTOMDRAW *)lp;
                    switch (cd->nmcd.dwDrawStage) {
                    case CDDS_PREPAINT:
                        return CDRF_NOTIFYITEMDRAW;
                    case CDDS_ITEMPREPAINT:
                        {
                            unsigned int row = (unsigned int)cd->nmcd.dwItemSpec;
                            if (row < g->view.count) {
                                int lvl = g->view.rows[row].lvl;
                                if (lvl == PW_LVL_SUSPECT)
                                    cd->clrText = RGB(190, 30, 30);
                                else if (lvl == PW_LVL_WARN)
                                    cd->clrText = RGB(170, 100, 0);
                            }
                        }
                        return CDRF_NEWFONT;
                    }
                    return CDRF_DODEFAULT;
                }
                if (nh->code == NM_DBLCLK) {
                    int sel = (int)SendMessageW(g->list, LVM_GETNEXTITEM,
                                                (WPARAM)-1, LVNI_SELECTED);
                    if (sel >= 0 && (unsigned int)sel < g->view.count) {
                        const PW_EVENT *e = &g->view.rows[sel];
                        wchar_t body[2400], wapi[128], wtgt[1200], wdet[1000];
                        char ts[40];
                        pw_ts_str(e->ts, ts, sizeof(ts));
                        pw_utf8_to_wide(e->api, wapi, 128);
                        pw_utf8_to_wide(e->target, wtgt, 1200);
                        pw_utf8_to_wide(e->detail, wdet, 1000);
                        _snwprintf(body, 2400,
                                   L"时间: %hs\n线程: %u\n类别: %hs\n级别: %hs\n"
                                   L"API: %s\n\n目标:\n%s\n\n详情:\n%s\n\n"
                                   L"返回值: %d   字节数: %u",
                                   ts, e->tid, pw_cat_name(e->cat),
                                   pw_lvl_name(e->lvl), wapi, wtgt, wdet,
                                   e->result, e->size);
                        body[2399] = 0;
                        MessageBoxW(hwnd, body, L"事件详情", MB_OK | MB_ICONINFORMATION);
                    }
                    return 0;
                }
            }
        }
        break;

    case WM_KEYDOWN:
        if (wp == VK_ESCAPE) { ShowWindow(hwnd, SW_MINIMIZE); return 0; }
        if (wp == 'C' && (GetKeyState(VK_CONTROL) & 0x8000)) { copy_visible(g, 1); return 0; }
        if (wp == VK_RETURN && GetFocus() == g->editSearch) {
            GetWindowTextW(g->editSearch, g->search, 128);
            rebuild_view(g);
            refresh_list(g);
            return 0;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        g->alive = 0;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* ------------------------------------------------------------- construction */

static void create_children(GuiState *g, HINSTANCE inst)
{
    LVCOLUMNW col;
    int i;

    g->btnPause = CreateWindowW(L"BUTTON", L"暂停", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                0, 0, 0, 0, g->hwnd, (HMENU)ID_BTN_PAUSE, inst, NULL);
    g->btnClear = CreateWindowW(L"BUTTON", L"清空", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                0, 0, 0, 0, g->hwnd, (HMENU)ID_BTN_CLEAR, inst, NULL);
    g->btnExport = CreateWindowW(L"BUTTON", L"导出日志", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                0, 0, 0, 0, g->hwnd, (HMENU)ID_BTN_EXPORT, inst, NULL);
    g->btnCopy = CreateWindowW(L"BUTTON", L"复制全部", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                0, 0, 0, 0, g->hwnd, (HMENU)ID_BTN_COPY, inst, NULL);
    g->btnWeb = CreateWindowW(L"BUTTON", L"打开 WebUI", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                0, 0, 0, 0, g->hwnd, (HMENU)ID_BTN_WEB, inst, NULL);
    g->cmbCat = CreateWindowW(L"COMBOBOX", NULL,
                              WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                              0, 0, 0, 0, g->hwnd, (HMENU)ID_CMB_CAT, inst, NULL);
    g->chkSuspect = CreateWindowW(L"BUTTON", L"只看可疑",
                                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                  0, 0, 0, 0, g->hwnd, (HMENU)ID_CHK_SUSPECT, inst, NULL);
    g->editSearch = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                    0, 0, 0, 0, g->hwnd, (HMENU)ID_EDIT_SEARCH, inst, NULL);
    g->status = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
                              0, 0, 0, 0, g->hwnd, (HMENU)ID_STATUS, inst, NULL);

    g->list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                              WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_OWNERDATA |
                              LVS_SHOWSELALWAYS | WS_TABSTOP,
                              0, 0, 0, 0, g->hwnd, (HMENU)ID_LIST, inst, NULL);

    SendMessageW(g->list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                 LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    memset(&col, 0, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    for (i = 0; i < 6; i++) {
        col.iSubItem = i;
        col.pszText = (LPWSTR)COL_TITLE[i];
        col.cx = COL_WIDTH[i];
        SendMessageW(g->list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col);
    }

    SendMessageW(g->cmbCat, CB_ADDSTRING, 0, (LPARAM)L"全部分类");
    SendMessageW(g->cmbCat, CB_ADDSTRING, 0, (LPARAM)L"文件");
    SendMessageW(g->cmbCat, CB_ADDSTRING, 0, (LPARAM)L"注册表");
    SendMessageW(g->cmbCat, CB_ADDSTRING, 0, (LPARAM)L"网络");
    SendMessageW(g->cmbCat, CB_ADDSTRING, 0, (LPARAM)L"HTTP");
    SendMessageW(g->cmbCat, CB_ADDSTRING, 0, (LPARAM)L"进程");
    SendMessageW(g->cmbCat, CB_ADDSTRING, 0, (LPARAM)L"模块");
    SendMessageW(g->cmbCat, CB_ADDSTRING, 0, (LPARAM)L"内存");
    SendMessageW(g->cmbCat, CB_SETCURSEL, 0, 0);

    if (g->font) {
        HWND kids[] = { g->btnPause, g->btnClear, g->btnExport, g->btnCopy, g->btnWeb,
                        g->cmbCat, g->chkSuspect, g->editSearch, g->status, g->list };
        size_t k;
        for (k = 0; k < sizeof(kids) / sizeof(kids[0]); k++)
            SendMessageW(kids[k], WM_SETFONT, (WPARAM)g->font, TRUE);
    }
}

static DWORD WINAPI gui_thread(LPVOID param)
{
    HINSTANCE inst = (HINSTANCE)param;
    WNDCLASSEXW wc;
    MSG msg;
    wchar_t title[300];
    char t8[300];
    int x, y;

    /* The window's own file/registry traffic (fonts, theme, clipboard) is not
     * activity of the monitored program. */
    pw_suppress_enter();
    pw_trace("gui: thread start");

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ProcWatchMonitorWnd";
    RegisterClassExW(&wc);

    memset(&g_gui, 0, sizeof(g_gui));
    g_gui.pull = (PW_EVENT *)malloc(sizeof(PW_EVENT) * PULL_CHUNK);
    g_gui.view.rows = (PW_EVENT *)malloc(sizeof(PW_EVENT) * VIEW_CAP);
    if (!g_gui.pull || !g_gui.view.rows) {
        SetEvent(g_ready);
        return 0;
    }

    /* Cascade so several injected processes do not stack perfectly. */
    x = 80 + (int)(g_pid % 8) * 34;
    y = 60 + (int)(g_pid % 5) * 30;

    _snprintf(t8, sizeof(t8), "ProcWatch 行为监控  -  %s  [PID %lu]",
              g_exe_name, (unsigned long)g_pid);
    t8[sizeof(t8) - 1] = 0;
    pw_utf8_to_wide(t8, title, 300);

    g_gui.hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, L"ProcWatchMonitorWnd", title,
                                 WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                 x, y, 1180, 640, NULL, NULL, inst, NULL);
    pw_trace("gui: CreateWindowExW -> %p", (void *)g_gui.hwnd);
    if (!g_gui.hwnd) {
        /* No desktop access (service, session 0) - the WebUI is the fallback. */
        SetEvent(g_ready);
        return 0;
    }

    g_gui.font = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                             L"Microsoft YaHei UI");
    create_children(&g_gui, inst);
    pw_trace("gui: children created");

    /* The WM_SIZE that arrives during CreateWindowExW ran while there were no
     * children yet, so the controls were created with a zero-sized rect. Lay
     * them out explicitly now that they exist. */
    {
        RECT rc;
        GetClientRect(g_gui.hwnd, &rc);
        layout(&g_gui, rc.right, rc.bottom);
    }

    g_gui.alive = 1;
    g_gui.lastSeq = pw_log_last_seq(&g_log);
    refresh_list(&g_gui);
    pw_trace("gui: list refreshed");
    SetTimer(g_gui.hwnd, ID_TIMER, 250, NULL);
    SetEvent(g_ready);
    pw_trace("gui: ready signalled");

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN &&
            GetFocus() == g_gui.editSearch) {
            GetWindowTextW(g_gui.editSearch, g_gui.search, 128);
            rebuild_view(&g_gui);
            refresh_list(&g_gui);
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    view_free(&g_gui);
    free(g_gui.pull);
    g_gui.pull = NULL;
    return 0;
}

/* ------------------------------------------------------------------- public */

int pw_gui_start(void)
{
    DWORD tid;

    if (g_thread) return g_gui.alive;
    g_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_ready) return 0;

    g_thread = CreateThread(NULL, 0, gui_thread, (LPVOID)g_self, 0, &tid);
    if (!g_thread) return 0;

    WaitForSingleObject(g_ready, 5000);
    CloseHandle(g_ready);
    g_ready = NULL;
    return g_gui.alive;
}

void pw_gui_stop(void)
{
    if (g_gui.hwnd) PostMessageW(g_gui.hwnd, WM_CLOSE, 0, 0);
}

int pw_gui_running(void)
{
    return g_gui.alive;
}

void pw_gui_refresh(void)
{
    if (g_gui.hwnd) PostMessageW(g_gui.hwnd, WM_TIMER, ID_TIMER, 0);
}

int pw_gui_export(char *outPath, int outsz, int csv)
{
    if (!g_gui.alive) return 0;
    return export_rows(&g_gui, outPath, outsz, csv);
}
