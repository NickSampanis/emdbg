#include "app.h"

#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void log_line(app_state *app, dbg_out_kind kind, const char *text, size_t len)
{
    int slot;

    if (app->log_count < APP_LOG_LINES) {
        slot = (app->log_first + app->log_count++) % APP_LOG_LINES;
    } else {
        slot = app->log_first;
        app->log_first = (app->log_first + 1) % APP_LOG_LINES;
    }
    if (len >= APP_LOG_LINE_SIZE)
        len = APP_LOG_LINE_SIZE - 1;
    memcpy(app->log[slot], text, len);
    app->log[slot][len] = '\0';
    app->log_kind[slot] = kind;
    app->log_scroll = true;
    app->log_total++;
}

void app_log(app_state *app, dbg_out_kind kind, const char *text)
{
    const char *nl;

    while (*text) {
        nl = strchr(text, '\n');
        if (!nl) {
            log_line(app, kind, text, strlen(text));
            break;
        }
        log_line(app, kind, text, (size_t)(nl - text));
        text = nl + 1;
    }
}

/* --- command history -------------------------------------------------------------------- */

static const char *history_at(const app_state *app, int i)
{
    return app->history[(app->hist_first + i) % APP_HISTORY];
}

/* Remember a typed command; skips blank lines and repeats of the last entry. */
static void history_add(app_state *app, const char *line)
{
    int slot;

    app->hist_pos = -1;
    if (!line[0] || (app->hist_count && !strcmp(history_at(app, app->hist_count - 1), line)))
        return;
    if (app->hist_count < APP_HISTORY) {
        slot = (app->hist_first + app->hist_count++) % APP_HISTORY;
    } else {
        slot = app->hist_first;
        app->hist_first = (app->hist_first + 1) % APP_HISTORY;
    }
    snprintf(app->history[slot], sizeof app->history[slot], "%s", line);
}

/* Up / Down in the command input walk the history; Down past the newest gives an
 * empty line. */
static int history_callback(ImGuiInputTextCallbackData *data)
{
    app_state *app = (app_state *)data->UserData;
    int        pos = app->hist_pos;

    if (data->EventFlag != ImGuiInputTextFlags_CallbackHistory)
        return 0;
    if (data->EventKey == ImGuiKey_UpArrow) {
        if (pos == -1)
            pos = app->hist_count - 1;          /* stays -1 when the history is empty */
        else if (pos > 0)
            pos--;
    } else if (data->EventKey == ImGuiKey_DownArrow) {
        if (pos != -1 && ++pos >= app->hist_count)
            pos = -1;
    }
    if (pos == app->hist_pos)
        return 0;
    app->hist_pos = pos;
    ImGuiInputTextCallbackData_DeleteChars(data, 0, data->BufTextLen);
    ImGuiInputTextCallbackData_InsertChars(data, 0, pos == -1 ? "" : history_at(app, pos), NULL);
    return 0;
}

/* --- pane ------------------------------------------------------------------------------- */

static ImU32 kind_color(dbg_out_kind kind)
{
    switch (kind) {
    case DBG_OUT_ECHO:   return COL_DIM;
    case DBG_OUT_ERROR:  return COL_ERROR;
    case DBG_OUT_TARGET: return COL_TARGET;
    case DBG_OUT_NORMAL: break;
    }
    return igGetColorU32_Col(ImGuiCol_Text, 1.0f);
}

/* --- log selection and copy ------------------------------------------------------------- */

/* Number of the index-th visible line, stable while the ring buffer wraps. */
static uint64_t log_number(const app_state *app, int index)
{
    return app->log_total - (uint64_t)app->log_count + (uint64_t)index;
}

static bool log_selected(const app_state *app, uint64_t number)
{
    uint64_t low;
    uint64_t high;

    if (!app->log_has_sel)
        return false;
    low = app->log_sel_anchor < app->log_sel_end ? app->log_sel_anchor : app->log_sel_end;
    high = app->log_sel_anchor < app->log_sel_end ? app->log_sel_end : app->log_sel_anchor;
    return number >= low && number <= high;
}

/* Copies the selected lines (or all of them) to the clipboard, one per line. */
static void log_copy(app_state *app, bool all)
{
    char  *text;
    size_t len;
    size_t line_len;
    int    index;
    int    slot;

    len = 0;
    text = malloc((size_t)app->log_count * APP_LOG_LINE_SIZE + 1);
    if (!text)
        return;
    for (index = 0; index < app->log_count; index++) {
        if (!all && !log_selected(app, log_number(app, index)))
            continue;
        slot = (app->log_first + index) % APP_LOG_LINES;
        line_len = strlen(app->log[slot]);
        memcpy(text + len, app->log[slot], line_len);
        len += line_len;
        text[len++] = '\n';
    }
    text[len] = '\0';
    igSetClipboardText(text);
    free(text);
}

static void log_select_all(app_state *app)
{
    if (!app->log_count)
        return;
    app->log_sel_anchor = log_number(app, 0);
    app->log_sel_end = log_number(app, app->log_count - 1);
    app->log_has_sel = true;
}

/* One log line: a selectable row under the coloured text. Click selects, Shift+click
 * extends, dragging extends to the line under the mouse. */
static void log_row(app_state *app, int index)
{
    uint64_t number;
    float    start_x;
    int      slot;

    number = log_number(app, index);
    slot = (app->log_first + index) % APP_LOG_LINES;
    start_x = igGetCursorPosX();
    igPushID_Int(index);
    igSelectable_Bool("##line", log_selected(app, number), ImGuiSelectableFlags_AllowOverlap,
                      v2(0, 0));
    if (igIsItemClicked(ImGuiMouseButton_Left)) {
        if (!igGetIO_Nil()->KeyShift || !app->log_has_sel)
            app->log_sel_anchor = number;
        app->log_sel_end = number;
        app->log_has_sel = true;
        app->log_dragging = true;
    } else if (app->log_dragging &&
               igIsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem)) {
        app->log_sel_end = number;
    }
    igPopID();
    igSameLine(start_x, 0);
    text_col(kind_color(app->log_kind[slot]), app->log[slot]);
}

static void log_menu(app_state *app)
{
    if (!igBeginPopupContextWindow("log_menu", ImGuiPopupFlags_MouseButtonRight))
        return;
    if (igMenuItem_Bool("Copy", "Ctrl+C", false, app->log_has_sel))
        log_copy(app, false);
    if (igMenuItem_Bool("Copy all", NULL, false, app->log_count > 0))
        log_copy(app, true);
    if (igMenuItem_Bool("Select all", "Ctrl+A", false, app->log_count > 0))
        log_select_all(app);
    igSeparator();
    if (igMenuItem_Bool("Clear", NULL, false, app->log_count > 0))
        app_exec(app, "clear");
    igEndPopup();
}

static void log_view(app_state *app)
{
    ImGuiListClipper *clipper;
    int               index;

    clipper = ImGuiListClipper_ImGuiListClipper();
    ImGuiListClipper_Begin(clipper, app->log_count, -1.0f);
    while (ImGuiListClipper_Step(clipper))
        for (index = clipper->DisplayStart; index < clipper->DisplayEnd; index++)
            log_row(app, index);
    ImGuiListClipper_End(clipper);
    ImGuiListClipper_destroy(clipper);

    if (!igIsMouseDown_Nil(ImGuiMouseButton_Left))
        app->log_dragging = false;
    log_menu(app);
    if (igIsWindowFocused(0)) {
        if (igIsKeyChordPressed_Nil(ImGuiMod_Ctrl | ImGuiKey_C) && app->log_has_sel)
            log_copy(app, false);
        if (igIsKeyChordPressed_Nil(ImGuiMod_Ctrl | ImGuiKey_A))
            log_select_all(app);
    }
    if (app->log_scroll)
        igSetScrollY_Float(FLT_MAX);     /* clamped to the bottom on the next frame */
    app->log_scroll = false;
}

void pane_command(app_state *app)
{
    float input_h;

    if (!app->show_cmd)
        return;
    if (!igBegin(WIN_CMD, &app->show_cmd, 0)) {
        igEnd();
        return;
    }

    input_h = igGetFrameHeightWithSpacing();
    if (igBeginChild_Str("log", v2(0, -input_h), 0, ImGuiWindowFlags_HorizontalScrollbar))
        log_view(app);
    igEndChild();

    igSetNextItemWidth(-1);
    if (igInputText("##cmd", app->cmd_input, sizeof app->cmd_input,
                    ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackHistory,
                    history_callback, app)) {
        history_add(app, app->cmd_input);
        app_exec(app, app->cmd_input);   /* an empty line repeats the last step / dump */
        app->cmd_input[0] = '\0';
        igSetKeyboardFocusHere(-1);      /* keep focus in the input after Enter */
    }
    igEnd();
}
