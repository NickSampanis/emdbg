/* Source pane: the source line of the selected address (the pc after a stop), from symbols
 * loaded with lds. Click selects a line, double-click / F2 toggles a breakpoint on it. */
#include "app.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAB_WIDTH    4
#define MAX_BP_LINES 256

void source_free(app_state *app)
{
    free(app->src_text);
    free(app->src_lines);
    app->src_text = NULL;
    app->src_lines = NULL;
    app->src_line_count = 0;
}

static char *read_whole_file(const char *path, size_t *size)
{
    FILE *file;
    char *data;
    long  length;

    data = NULL;
    file = fopen(path, "rb");
    if (!file)
        return NULL;
    if (fseek(file, 0, SEEK_END) == 0) {
        length = ftell(file);
        if (length >= 0 && fseek(file, 0, SEEK_SET) == 0) {
            data = malloc((size_t)length + 1);
            if (data && fread(data, 1, (size_t)length, file) != (size_t)length) {
                free(data);
                data = NULL;
            }
            *size = (size_t)length;
        }
    }
    fclose(file);
    return data;
}

/* Reads the whole file, expands tabs and splits it into NUL-terminated lines. */
static bool source_load(app_state *app, const char *path)
{
    char    *raw;
    size_t   size;
    size_t   index;
    size_t   out;
    size_t   tabs;
    size_t   newlines;
    uint32_t count;
    int      column;

    size = 0;
    out = 0;
    tabs = 0;
    newlines = 0;
    count = 1;
    column = 0;
    raw = read_whole_file(path, &size);
    if (!raw)
        return false;
    for (index = 0; index < size; index++) {
        tabs += raw[index] == '\t';
        newlines += raw[index] == '\n';
    }
    app->src_text = malloc(size + tabs * TAB_WIDTH + 1);
    app->src_lines = malloc((newlines + 1) * sizeof *app->src_lines);
    if (!app->src_text || !app->src_lines) {
        free(raw);
        source_free(app);
        return false;
    }

    app->src_lines[0] = 0;
    for (index = 0; index < size; index++) {
        if (raw[index] == '\r')
            continue;
        if (raw[index] == '\n') {
            app->src_text[out++] = '\0';
            app->src_lines[count++] = (uint32_t)out;
            column = 0;
        } else if (raw[index] == '\t') {
            do {
                app->src_text[out++] = ' ';
                column++;
            } while (column % TAB_WIDTH);
        } else {
            app->src_text[out++] = raw[index];
            column++;
        }
    }
    app->src_text[out] = '\0';
    if (count > 1 && app->src_lines[count - 1] == out)   /* the file ends with a newline */
        count--;
    app->src_line_count = count;
    free(raw);
    return true;
}

/* A caller frame's line is the call's: look up the byte before the return address. */
static uint64_t source_lookup(const app_state *app, uint64_t addr)
{
    return app->view_frame && addr == app->frame_pc ? addr - 1 : addr;
}

/* Shows the file and line of the selected address. Returns the line to scroll to, or 0. */
static uint32_t follow_selection(app_state *app)
{
    dbg_source location;

    app->src_module_count = dbg_module_count(app->dbg);
    app->src_refresh = false;
    if (!dbg_source_at(app->dbg, source_lookup(app, app->selected), &location))
        return 0;
    if (strcmp(location.file, app->src_file) != 0) {
        source_free(app);
        snprintf(app->src_file, sizeof app->src_file, "%s", location.file);
        app->src_found = location.file_found && source_load(app, location.file);
    }
    app->src_sel_line = location.line;
    app->src_sel_anchor = location.line;
    return location.line;
}

static void toggle_line(app_state *app, uint32_t line)
{
    uint64_t addr;

    if (dbg_line_addr(app->dbg, app->src_file, line, &addr) == DBG_OK)
        app_toggle_bp(app, addr);
    else
        app_log(app, DBG_OUT_ERROR, "no code at or after this line\n");
}

/* Click selects a line (and its address); Shift+click extends the range for copying. */
static void select_line(app_state *app, uint32_t line, bool extend)
{
    uint64_t addr;

    app->src_sel_line = line;
    if (!extend || !app->src_sel_anchor)
        app->src_sel_anchor = line;
    if (dbg_line_addr(app->dbg, app->src_file, line, &addr) == DBG_OK)
        app_select(app, addr, PANE_SOURCE);
}

static bool line_selected(const app_state *app, uint32_t line)
{
    uint32_t first;
    uint32_t last;

    if (!app->src_sel_line || !app->src_sel_anchor)
        return false;
    first = app->src_sel_anchor < app->src_sel_line ? app->src_sel_anchor : app->src_sel_line;
    last = app->src_sel_anchor < app->src_sel_line ? app->src_sel_line : app->src_sel_anchor;
    return line >= first && line <= last;
}

static void copy_lines(app_state *app)
{
    char    *text;
    size_t   len;
    size_t   line_len;
    uint32_t first;
    uint32_t last;
    uint32_t line;

    len = 0;
    if (!app->src_sel_line || !app->src_sel_anchor)
        return;
    first = app->src_sel_anchor < app->src_sel_line ? app->src_sel_anchor : app->src_sel_line;
    last = app->src_sel_anchor < app->src_sel_line ? app->src_sel_line : app->src_sel_anchor;
    if (last > app->src_line_count)
        last = app->src_line_count;
    for (line = first; line <= last; line++)
        len += strlen(app->src_text + app->src_lines[line - 1]) + 1;
    text = malloc(len + 1);
    if (!text)
        return;
    len = 0;
    for (line = first; line <= last; line++) {
        line_len = strlen(app->src_text + app->src_lines[line - 1]);
        memcpy(text + len, app->src_text + app->src_lines[line - 1], line_len);
        len += line_len;
        text[len++] = '\n';
    }
    text[len] = '\0';
    igSetClipboardText(text);
    free(text);
}

static bool is_word_char(char ch)
{
    return isalnum((unsigned char)ch) || ch == '_';
}

/* The identifier at horizontal offset x (pixels) into text, or "" if there is none. */
static void word_at(const char *text, float x, char *word, size_t cap)
{
    size_t length;
    size_t index;
    size_t start;
    size_t end;

    word[0] = '\0';
    length = strlen(text);
    if (x < 0)
        return;
    for (index = 0; index < length; index++)
        if (igCalcTextSize(text, text + index + 1, false, -1.0f).x > x)
            break;
    if (index >= length || !is_word_char(text[index]))
        return;
    start = index;
    while (start > 0 && is_word_char(text[start - 1]))
        start--;
    end = index;
    while (end < length && is_word_char(text[end]))
        end++;
    if (end - start >= cap)
        end = start + cap - 1;
    memcpy(word, text + start, end - start);
    word[end - start] = '\0';
}

static void insert_in_command(app_state *app, const char *word)
{
    size_t len;

    len = strlen(app->cmd_input);
    snprintf(app->cmd_input + len, sizeof app->cmd_input - len, "%s%s",
             len && app->cmd_input[len - 1] != ' ' ? " " : "", word);
}

/* Right-click menu: the word under the mouse, then the selected lines. Returns a line to
 * toggle a breakpoint on, or 0. */
static uint32_t source_menu(app_state *app)
{
    char     label[192];
    char     command[160];
    uint64_t addr;
    uint32_t toggle;
    bool     known;

    toggle = 0;
    if (!igBeginPopup("source_menu", 0))
        return 0;
    if (app->src_word[0]) {
        snprintf(label, sizeof label, "Copy \"%s\"", app->src_word);
        if (igMenuItem_Bool(label, NULL, false, true))
            igSetClipboardText(app->src_word);
        snprintf(label, sizeof label, "Insert \"%s\" in the command line", app->src_word);
        if (igMenuItem_Bool(label, NULL, false, true))
            insert_in_command(app, app->src_word);
        known = dbg_sym_addr(app->dbg, app->src_word, strlen(app->src_word), &addr);
        snprintf(label, sizeof label, "Breakpoint on %s", app->src_word);
        if (igMenuItem_Bool(label, NULL, false, known)) {
            snprintf(command, sizeof command, "bp %s", app->src_word);
            app_exec(app, command);
        }
        igSeparator();
    }
    if (igMenuItem_Bool(app->src_sel_anchor != app->src_sel_line ? "Copy lines" : "Copy line",
                        "Ctrl+C", false, true))
        copy_lines(app);
    if (igMenuItem_Bool("Toggle breakpoint on line", "F2", false, true))
        toggle = app->src_menu_line;
    igEndPopup();
    return toggle;
}

/* Lines of the shown file that have exec breakpoints. */
static int collect_bp_lines(app_state *app, uint32_t *lines, bool *enabled)
{
    const dbg_bp *bp;
    dbg_source    location;
    int           count;
    int           index;

    count = 0;
    for (index = 0; index < dbg_bp_count(app->dbg) && count < MAX_BP_LINES; index++) {
        bp = dbg_bp_get(app->dbg, index);
        if (bp->type != EM_BP_EXEC || !dbg_source_at(app->dbg, bp->addr, &location) ||
            strcmp(location.file, app->src_file))
            continue;
        lines[count] = location.line;
        enabled[count] = bp->enabled;
        count++;
    }
    return count;
}

static uint32_t line_in_file(app_state *app, uint64_t addr)
{
    dbg_source location;

    if (dbg_get_state(app->dbg) != DBG_STATE_STOPPED ||
        !dbg_source_at(app->dbg, addr, &location) || strcmp(location.file, app->src_file))
        return 0;
    return location.line;
}

/* Draws the file; returns the line double-clicked, or 0. */
static uint32_t draw_lines(app_state *app, uint32_t scroll_line)
{
    ImGuiTableFlags   flags;
    ImGuiListClipper *clipper;
    uint32_t          bp_lines[MAX_BP_LINES];
    bool              bp_enabled[MAX_BP_LINES];
    int               bp_count;
    int               bp_index;
    int               index;
    int               row;
    uint32_t          pc_line;
    uint32_t          frame_line;
    uint32_t          line;
    uint32_t          toggle;
    uint32_t          menu_toggle;
    float             line_height;
    float             text_x;
    ImVec2            row_min;
    char              number[16];
    bool              right_clicked;
    bool              open_menu;

    toggle = 0;
    open_menu = false;
    flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_SizingFixedFit;
    pc_line = line_in_file(app, dbg_pc(app->dbg));
    frame_line = app->view_frame ? line_in_file(app, app->frame_pc - 1) : 0;
    bp_count = collect_bp_lines(app, bp_lines, bp_enabled);
    if (!igBeginTable("source", 3, flags, v2(0, 0), 0))
        return 0;
    line_height = igGetTextLineHeight();
    igTableSetupColumn("", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize,
                       line_height, 0);
    igTableSetupColumn("Line", ImGuiTableColumnFlags_WidthFixed, 0, 0);
    igTableSetupColumn("Text", ImGuiTableColumnFlags_WidthStretch, 0, 0);

    clipper = ImGuiListClipper_ImGuiListClipper();
    ImGuiListClipper_Begin(clipper, (int)app->src_line_count, -1.0f);
    if (scroll_line && scroll_line <= app->src_line_count)
        ImGuiListClipper_IncludeItemByIndex(clipper, (int)scroll_line - 1);
    while (ImGuiListClipper_Step(clipper)) {
        for (row = clipper->DisplayStart; row < clipper->DisplayEnd; row++) {
            line = (uint32_t)row + 1;
            bp_index = -1;
            for (index = 0; index < bp_count; index++)
                if (bp_lines[index] == line && (bp_index < 0 || bp_enabled[index]))
                    bp_index = index;

            igTableNextRow(0, 0);
            if (line == pc_line)
                igTableSetBgColor(ImGuiTableBgTarget_RowBg1, COL_PC_BG, -1);
            else if (line == frame_line)
                igTableSetBgColor(ImGuiTableBgTarget_RowBg1, COL_FRAME_BG, -1);
            else if (bp_index >= 0 && bp_enabled[bp_index])
                igTableSetBgColor(ImGuiTableBgTarget_RowBg1, COL_BP_BG, -1);

            igTableSetColumnIndex(0);
            igPushID_Int(row);
            igSelectable_Bool("##row", line_selected(app, line),
                              ImGuiSelectableFlags_SpanAllColumns, v2(0, 0));
            row_min = igGetItemRectMin();
            right_clicked = igIsItemClicked(ImGuiMouseButton_Right);
            if (igIsItemClicked(ImGuiMouseButton_Left)) {
                select_line(app, line, igGetIO_Nil()->KeyShift);
                app->src_dragging = true;
            } else if (app->src_dragging && line != app->src_sel_line &&
                       igIsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem)) {
                app->src_sel_line = line;
            }
            if (igIsItemHovered(0) && igIsMouseDoubleClicked_Nil(ImGuiMouseButton_Left))
                toggle = line;
            igPopID();
            if (bp_index >= 0)
                app_draw_bp_dot(row_min, line_height, bp_enabled[bp_index]);
            if (line == pc_line)
                app_draw_pc_arrow(row_min, line_height);
            else if (line == frame_line)
                app_draw_frame_arrow(row_min, line_height);
            if (line == scroll_line)
                igSetScrollHereY(0.3f);

            snprintf(number, sizeof number, "%u", line);
            igTableSetColumnIndex(1);
            text_col(COL_DIM, number);
            igTableSetColumnIndex(2);
            text_x = igGetCursorScreenPos().x;
            igTextUnformatted(app->src_text + app->src_lines[row], NULL);
            if (right_clicked) {
                word_at(app->src_text + app->src_lines[row], igGetMousePos().x - text_x,
                        app->src_word, sizeof app->src_word);
                app->src_menu_line = line;
                if (!line_selected(app, line))
                    select_line(app, line, false);
                open_menu = true;
            }
        }
    }
    ImGuiListClipper_End(clipper);
    ImGuiListClipper_destroy(clipper);
    if (!igIsMouseDown_Nil(ImGuiMouseButton_Left))
        app->src_dragging = false;
    if (open_menu)
        igOpenPopup_Str("source_menu", 0);
    menu_toggle = source_menu(app);
    if (menu_toggle)
        toggle = menu_toggle;
    igEndTable();
    return toggle;
}

void pane_source(app_state *app)
{
    uint32_t scroll_line;
    uint32_t toggle;

    scroll_line = 0;
    toggle = 0;
    if (!app->show_source)
        return;
    if (!igBegin(WIN_SOURCE, &app->show_source, 0) || !app->dbg) {
        igEnd();
        app->scroll_mask &= ~PANE_SOURCE;
        return;
    }

    if ((app->scroll_mask & PANE_SOURCE) || app->src_refresh ||
        app->src_module_count != dbg_module_count(app->dbg))
        scroll_line = follow_selection(app);
    app->scroll_mask &= ~PANE_SOURCE;

    if (!app->src_file[0]) {
        if (dbg_module_count(app->dbg))
            igTextDisabled("No source line for %016" PRIx64 ".", app->selected);
        else
            igTextDisabled("No symbols. Load them with lds <file> <base | start end>.");
    } else if (!app->src_found) {
        igTextWrapped("Source file not found: %s", app->src_file);
        if (igButton("Set source folders...", v2(0, 0)))
            app->open_paths = true;
    } else {
        toggle = draw_lines(app, scroll_line);
        if (igIsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
            if (igIsKeyChordPressed_Nil(ImGuiKey_F2) && app->src_sel_line)
                toggle = app->src_sel_line;
            if (igIsKeyChordPressed_Nil(ImGuiMod_Ctrl | ImGuiKey_C))
                copy_lines(app);
        }
    }
    igEnd();

    /* After the table: the command may change breakpoints and the selection. */
    if (toggle)
        toggle_line(app, toggle);
}
