/* Call Stack pane: frames from dbg_stack_walk, walked again after each refresh (stop or
 * command). Double-click a frame (or use its menu) to make it the selected frame: that
 * runs ".frame N", so Locals, Watch, dv and dx evaluate in that frame and the code panes
 * show it (layout.c, follow_frame). */
#include "app.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static bool add_frame(void *user, const dbg_frame *frame)
{
    app_state *app;

    app = (app_state *)user;
    if (app->stack_count >= APP_FRAMES)
        return false;
    app->stack_frames[app->stack_count] = *frame;
    if (!dbg_sym_format(app->dbg, frame->pc, app->stack_sites[app->stack_count],
                        sizeof app->stack_sites[0]))
        snprintf(app->stack_sites[app->stack_count], sizeof app->stack_sites[0],
                 "0x%016" PRIx64, frame->pc);
    app->stack_count++;
    return true;
}

static void switch_frame(app_state *app, uint32_t number)
{
    char line[32];

    snprintf(line, sizeof line, ".frame %x", number);
    app_exec(app, line);
}

static void copy_hex(uint64_t value)
{
    char text[24];

    snprintf(text, sizeof text, "%016" PRIX64, value);
    igSetClipboardText(text);
}

static void frame_menu(app_state *app, int index, int *switch_to)
{
    const dbg_frame *frame;

    if (!igBeginPopupContextItem("frame_menu", ImGuiPopupFlags_MouseButtonRight))
        return;
    frame = &app->stack_frames[index];
    if (igMenuItem_Bool("Switch to frame", "double-click", false,
                        frame->number != dbg_get_frame(app->dbg)))
        *switch_to = (int)frame->number;
    igSeparator();
    if (igMenuItem_Bool("Copy call site", NULL, false, true))
        igSetClipboardText(app->stack_sites[index]);
    if (igMenuItem_Bool("Copy address", NULL, false, true))
        copy_hex(frame->pc);
    if (igMenuItem_Bool("Copy return address", NULL, false, frame->have_return))
        copy_hex(frame->return_addr);
    if (igMenuItem_Bool("Copy stack pointer", NULL, false, true))
        copy_hex(frame->sp);
    igEndPopup();
}

static void draw_frames(app_state *app)
{
    ImGuiTableFlags  flags;
    const dbg_frame *frame;
    char             text[24];
    uint32_t         selected;
    int              index;
    int              switch_to;

    switch_to = -1;
    selected = dbg_get_frame(app->dbg);
    flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit;
    if (!igBeginTable("stack", 4, flags, v2(0, 0), 0))
        return;
    igTableSetupScrollFreeze(0, 1);
    igTableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 0, 0);
    igTableSetupColumn("Call Site", ImGuiTableColumnFlags_WidthStretch, 0, 0);
    igTableSetupColumn("Child-SP", ImGuiTableColumnFlags_WidthFixed, 0, 0);
    igTableSetupColumn("Return Address", ImGuiTableColumnFlags_WidthFixed, 0, 0);
    igTableHeadersRow();

    for (index = 0; index < app->stack_count; index++) {
        frame = &app->stack_frames[index];
        igTableNextRow(0, 0);
        if (index == 0)
            igTableSetBgColor(ImGuiTableBgTarget_RowBg1, COL_PC_BG, -1);
        else if (frame->number == selected)
            igTableSetBgColor(ImGuiTableBgTarget_RowBg1, COL_FRAME_BG, -1);

        igTableSetColumnIndex(0);
        igPushID_Int(index);
        snprintf(text, sizeof text, "%02x", frame->number);
        if (igSelectable_Bool(text, frame->number == selected,
                              ImGuiSelectableFlags_SpanAllColumns |
                              ImGuiSelectableFlags_AllowDoubleClick, v2(0, 0)) &&
            igIsMouseDoubleClicked_Nil(ImGuiMouseButton_Left))
            switch_to = (int)frame->number;
        frame_menu(app, index, &switch_to);
        igPopID();

        igTableSetColumnIndex(1);
        igTextUnformatted(app->stack_sites[index], NULL);
        igTableSetColumnIndex(2);
        snprintf(text, sizeof text, "%016" PRIX64, frame->sp);
        text_col(COL_ADDR, text);
        igTableSetColumnIndex(3);
        if (frame->have_return) {
            snprintf(text, sizeof text, "%016" PRIX64, frame->return_addr);
            text_col(COL_ADDR, text);
        } else {
            igTextDisabled("-");
        }
    }
    if (app->stack_count && !app->stack_frames[app->stack_count - 1].have_cfa) {
        igTableNextRow(0, 0);
        igTableSetColumnIndex(1);
        igTextDisabled("(no unwind information below here: load the module's symbols with lds)");
    }
    igEndTable();

    if (switch_to >= 0 && (uint32_t)switch_to != selected)
        switch_frame(app, (uint32_t)switch_to);
}

void pane_stack(app_state *app)
{
    if (!app->show_stack)
        return;
    if (!igBegin(WIN_STACK, &app->show_stack, 0)) {
        igEnd();
        return;
    }
    if (!app->dbg || dbg_get_state(app->dbg) == DBG_STATE_DISCONNECTED) {
        igTextDisabled("Not connected.");
    } else if (dbg_get_state(app->dbg) == DBG_STATE_RUNNING) {
        igTextDisabled("Target is running.");
    } else {
        if (!app->stack_loaded) {
            app->stack_loaded = true;
            app->stack_count = 0;
            dbg_stack_walk(app->dbg, APP_FRAMES, add_frame, app);
        }
        draw_frames(app);
    }
    igEnd();
}
