/* Disassembly pane: instructions from the current pc onwards, decoded by dbgeng (Zydis),
 * refreshed on every stop. Scrolling near the bottom decodes the next instructions. */
#include "app.h"

#include <inttypes.h>
#include <stdio.h>

#define LOAD_AHEAD_ROWS 8         /* decode more when this close to the last row */

#define COL_CALL  0xFFFFC080u     /* light blue */
#define COL_JUMP  0xFF60D0FFu     /* yellow */
#define COL_RET   0xFF8080FFu     /* light red */

static ImU32 flow_color(uint8_t flow)
{
    switch (flow) {
    case DBG_FLOW_CALL:
    case DBG_FLOW_INT:
    case DBG_FLOW_SYSCALL: return COL_CALL;
    case DBG_FLOW_JMP:
    case DBG_FLOW_JCC:     return COL_JUMP;
    case DBG_FLOW_RET:     return COL_RET;
    }
    return igGetColorU32_Col(ImGuiCol_Text, 1.0f);
}

static void copy_address(uint64_t addr)
{
    char text[24];

    snprintf(text, sizeof text, "%016" PRIX64, addr);
    igSetClipboardText(text);
}

/* "0000000000401000  31 C0  xor eax, eax" */
static void copy_line(const dbg_insn *in)
{
    char     text[192];
    uint32_t k;
    int      n;

    n = snprintf(text, sizeof text, "%016" PRIX64 " ", in->addr);
    for (k = 0; k < in->len; k++)
        n += snprintf(text + n, sizeof text - (size_t)n, " %02X", in->bytes[k]);
    snprintf(text + n, sizeof text - (size_t)n, "  %s", in->text);
    igSetClipboardText(text);
}

/* Right-click menu of one instruction row. */
static void row_menu(app_state *app, const dbg_insn *in)
{
    if (!igBeginPopupContextItem("ctx", ImGuiPopupFlags_MouseButtonRight))
        return;
    app->selected = in->addr;
    if (igMenuItem_Bool(dbg_bp_find(app->dbg, in->addr) ? "Remove breakpoint" : "Set breakpoint",
                        "F2", false, true))
        app_toggle_bp(app, in->addr);
    igSeparator();
    if (igMenuItem_Bool("Copy address", "Ctrl+C", false, true))
        copy_address(in->addr);
    if (igMenuItem_Bool("Copy instruction", NULL, false, true))
        igSetClipboardText(in->text);
    if (igMenuItem_Bool("Copy line", NULL, false, true))
        copy_line(in);
    if (in->has_target && igMenuItem_Bool("Copy branch target", NULL, false, true))
        copy_address(in->target);
    igEndPopup();
}

/* One instruction row. Returns true if it was double-clicked (toggle a breakpoint). */
static bool draw_row(app_state *app, uint32_t i, uint64_t pc, float line_h, int scroll_index)
{
    const dbg_insn *in;
    const dbg_bp   *bp;
    ImVec2          rmin;
    char            text[48];
    char            symbol[160];
    bool            is_pc, is_frame, toggle = false;
    uint32_t        k;
    int             n;

    in = &app->code[i];
    is_pc = in->addr == pc;
    is_frame = app->view_frame && in->addr == app->frame_pc;
    igTableNextRow(0, 0);
    if (is_pc)
        igTableSetBgColor(ImGuiTableBgTarget_RowBg1, COL_PC_BG, -1);
    else if (is_frame)
        igTableSetBgColor(ImGuiTableBgTarget_RowBg1, COL_FRAME_BG, -1);

    bp = dbg_bp_find(app->dbg, in->addr);
    if (bp && bp->enabled && !is_pc && !is_frame)
        igTableSetBgColor(ImGuiTableBgTarget_RowBg1, COL_BP_BG, -1);

    igTableSetColumnIndex(0);
    igPushID_Int((int)i);
    if (igSelectable_Bool("##row", in->addr == app->selected,
                          ImGuiSelectableFlags_SpanAllColumns, v2(0, 0)))
        app_select(app, in->addr, PANE_DISASM);
    rmin = igGetItemRectMin();
    if (igIsItemHovered(0) && igIsMouseDoubleClicked_Nil(ImGuiMouseButton_Left))
        toggle = true;
    row_menu(app, in);
    igPopID();
    if (bp)
        app_draw_bp_dot(rmin, line_h, bp->enabled);
    if (is_pc)
        app_draw_pc_arrow(rmin, line_h);
    else if (is_frame)
        app_draw_frame_arrow(rmin, line_h);
    if ((int)i == scroll_index)
        igSetScrollHereY(0.3f);

    snprintf(text, sizeof text, "%016" PRIX64, in->addr);
    igTableSetColumnIndex(1);
    text_col(COL_ADDR, text);

    n = 0;
    for (k = 0; k < in->len && n + 4 < (int)sizeof text; k++)
        n += snprintf(text + n, sizeof text - (size_t)n, "%02X ", in->bytes[k]);
    text[n] = '\0';
    igTableSetColumnIndex(2);
    text_col(COL_DIM, text);

    igTableSetColumnIndex(3);
    text_col(in->valid ? flow_color(in->flow) : COL_DIM, in->text);
    if (in->has_target && dbg_sym_format(app->dbg, in->target, symbol, sizeof symbol)) {
        igSameLine(0, -1);
        text_col(COL_DIM, symbol);
    }
    return toggle;
}

/* Row of `addr` in the code buffer, or -1. */
static int code_index(const app_state *app, uint64_t addr)
{
    uint32_t i;

    for (i = 0; i < app->code_len; i++)
        if (app->code[i].addr == addr)
            return (int)i;
    return -1;
}

void pane_disasm(app_state *app)
{
    ImGuiTableFlags   flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV |
                              ImGuiTableFlags_SizingFixedFit;
    ImGuiListClipper *clipper;
    uint64_t          toggle_addr = 0;
    bool              do_toggle = false;
    bool              load_more = false;
    float             line_h;
    uint64_t          pc;
    int               scroll_index = -1;
    int               i;

    if (!app->show_disasm)
        return;
    if (!igBegin(WIN_DISASM, &app->show_disasm, 0)) {
        igEnd();
        app->scroll_mask &= ~PANE_DISASM;
        return;
    }

    if (!app->dbg || !dbg_regs(app->dbg)) {
        igTextDisabled(app->dbg && dbg_get_state(app->dbg) == DBG_STATE_RUNNING
                           ? "Target is running." : "Not connected.");
        igEnd();
        app->scroll_mask &= ~PANE_DISASM;
        return;
    }
    /* Another pane selected an address that is not in the buffer: show code from there. */
    if ((app->scroll_mask & PANE_DISASM) && app->selected) {
        scroll_index = code_index(app, app->selected);
        if (scroll_index < 0) {
            app_code_load(app, app->selected);
            scroll_index = code_index(app, app->selected);
        }
    }
    if (!app->code_len) {
        igTextDisabled("Cannot read memory at %016" PRIx64 ".", app->code_addr);
        igEnd();
        app->scroll_mask &= ~PANE_DISASM;
        return;
    }

    if (igBeginTable("disasm", 4, flags, v2(0, 0), 0)) {
        line_h = igGetTextLineHeight();
        igTableSetupScrollFreeze(0, 1);
        igTableSetupColumn("", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, line_h, 0);
        igTableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 0, 0);
        igTableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 0, 0);
        igTableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch, 0, 0);
        igTableHeadersRow();

        pc = dbg_pc(app->dbg);
        clipper = ImGuiListClipper_ImGuiListClipper();
        ImGuiListClipper_Begin(clipper, (int)app->code_len, -1.0f);
        if (scroll_index >= 0)
            ImGuiListClipper_IncludeItemByIndex(clipper, scroll_index);
        while (ImGuiListClipper_Step(clipper)) {
            for (i = clipper->DisplayStart; i < clipper->DisplayEnd; i++) {
                if (draw_row(app, (uint32_t)i, pc, line_h, scroll_index)) {
                    toggle_addr = app->code[i].addr;
                    do_toggle = true;
                }
            }
        }
        ImGuiListClipper_End(clipper);
        ImGuiListClipper_destroy(clipper);

        /* Near the bottom (or the code does not fill the pane): decode the next chunk. */
        if (!app->code_end && igGetScrollY() >= igGetScrollMaxY() - line_h * LOAD_AHEAD_ROWS)
            load_more = true;
        if (app->code_end) {
            igTableNextRow(0, 0);
            igTableSetColumnIndex(3);
            igTextDisabled(app->code_len >= APP_CODE_MAX ? "(row limit reached)"
                                                         : "(memory not readable after here)");
        }
        igEndTable();
    }

    /* Ctrl+C copies the selected address; F2 toggles a breakpoint on it (x64dbg). */
    if (igIsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
        if (igIsKeyChordPressed_Nil(ImGuiMod_Ctrl | ImGuiKey_C))
            copy_address(app->selected);
        if (igIsKeyChordPressed_Nil(ImGuiKey_F2)) {
            toggle_addr = app->selected;
            do_toggle = true;
        }
    }
    app->scroll_mask &= ~PANE_DISASM;
    igEnd();

    /* After the table: these change app->code. */
    if (load_more)
        app_code_more(app);
    if (do_toggle)
        app_toggle_bp(app, toggle_addr);
}
