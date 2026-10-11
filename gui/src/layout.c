/* App lifetime, dbgeng callbacks, main menu, toolbar, dockspace and the default layout. */
#include "app.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- dbgeng callbacks ---------------------------------------------------------------- */

static void on_output(void *user, dbg_out_kind kind, const char *text)
{
    app_log((app_state *)user, kind, text);
}

static void on_event(void *user, const dbg_event *ev)
{
    app_state *app = (app_state *)user;

    switch (ev->kind) {
    case DBG_EV_STOPPED:
        app->stop_pending = true;
        app->last_reason = ev->reason;
        break;
    case DBG_EV_DISCONNECTED:
        app->have_last = false;
        app->have_prev = false;
        app->code_len = 0;
        app->eval_dirty = true;
        break;
    case DBG_EV_CONNECTED:
    case DBG_EV_RUNNING:
        break;
    }
}

/* After a stop: remember registers for change highlighting and fetch code at rip. */
static void handle_stop(app_state *app)
{
    const em_x86_regs *regs = dbg_regs(app->dbg);

    app->stop_pending = false;
    app->eval_dirty = true;
    if (!regs)
        return;
    app->prev_regs = app->last_regs;
    app->have_prev = app->have_last;
    app->last_regs = *regs;
    app->have_last = true;

    app_code_load(app, dbg_pc(app->dbg));
    app->view_frame = 0;
    app->frame_pc = app->code_addr;
    app_select(app, app->code_addr, 0);
}

/* Code shown for a caller frame starts at its function when the return address is close
 * enough to fit in the pane, so the call itself is visible. */
#define FRAME_CODE_CONTEXT 0x100

/* After .frame N (from the Call Stack pane or typed): show that frame in the code panes. */
static void follow_frame(app_state *app)
{
    dbg_frame  frame;
    dbg_symbol symbol;
    uint64_t   start;

    if (!app->dbg || dbg_get_state(app->dbg) != DBG_STATE_STOPPED ||
        dbg_get_frame(app->dbg) == app->view_frame)
        return;
    if (dbg_frame_info(app->dbg, &frame) != DBG_OK)
        return;
    app->view_frame = frame.number;
    app->frame_pc = frame.pc;
    start = frame.pc;
    if (frame.number && dbg_sym_name(app->dbg, frame.pc - 1, &symbol) && symbol.function &&
        symbol.offset + 1 < FRAME_CODE_CONTEXT)
        start = frame.pc - 1 - symbol.offset;
    app_code_load(app, start);
    app_select(app, frame.pc, 0);
}

/* --- lifetime ------------------------------------------------------------------------ */

void app_init(app_state *app)
{
    dbg_callbacks cb;

    memset(app, 0, sizeof *app);
    app->show_disasm = true;
    app->show_source = true;
    app->show_regs   = true;
    app->show_cmd    = true;
    app->show_locals = true;
    app->show_watch  = true;
    app->show_stack  = true;
    app->watch_edit  = -1;
    eval_refresh(app);
    strcpy(app->target_addr, "127.0.0.1:4242");
    app->sel_reg = -1;
    app->hist_pos = -1;

    app->code = malloc(APP_CODE_MAX * sizeof *app->code);
    cb.output = on_output;
    cb.event  = on_event;
    cb.user   = app;
    app->dbg = dbg_create(&cb);
    settings_register(app);
    if (!app->dbg)
        app_log(app, DBG_OUT_ERROR, "failed to initialise dbgeng\n");
    else
        app_log(app, DBG_OUT_NORMAL, "Not connected. Start a stub (e.g. emstub_fake_target) "
                                     "and press Connect, or type .connect host:port\n");
}

void app_shutdown(app_state *app)
{
    dbg_destroy(app->dbg);
    app->dbg = NULL;
    source_free(app);
    free(app->code);
    app->code = NULL;
}

void app_code_load(app_state *app, uint64_t addr)
{
    app->code_addr = addr;
    app->code_len = 0;
    app->code_end = false;
    app_code_more(app);
}

void app_code_more(app_state *app)
{
    const dbg_insn *last;
    uint64_t        next;
    uint32_t        want;
    uint32_t        count;

    if (!app->code || !app->dbg || app->code_end)
        return;
    if (app->code_len >= APP_CODE_MAX) {
        app->code_end = true;
        return;
    }
    last = app->code_len ? &app->code[app->code_len - 1] : NULL;
    next = last ? last->addr + last->len : app->code_addr;
    want = APP_CODE_MAX - app->code_len < APP_CODE_INSNS ? APP_CODE_MAX - app->code_len
                                                          : APP_CODE_INSNS;
    count = 0;
    if (dbg_disasm(app->dbg, next, app->code + app->code_len, want, &count) != DBG_OK || !count) {
        app->code_end = true;
        return;
    }
    app->code_len += count;
}

void app_select(app_state *app, uint64_t addr, unsigned origin)
{
    app->selected = addr;
    app->scroll_mask = PANE_ALL & ~origin;
}

void app_toggle_bp(app_state *app, uint64_t addr)
{
    const dbg_bp *bp;
    char          line[64];

    bp = dbg_bp_find(app->dbg, addr);
    if (bp)
        snprintf(line, sizeof line, "bc %u", bp->id);
    else
        snprintf(line, sizeof line, "bp %" PRIx64, addr);
    app_exec(app, line);
}

void app_draw_pc_arrow(ImVec2 min, float h)
{
    ImDrawList *draw_list;
    float       center_x;
    float       center_y;
    float       radius;

    draw_list = igGetWindowDrawList();
    center_x = min.x + h * 0.5f;
    center_y = min.y + h * 0.5f;
    radius = h * 0.3f;
    ImDrawList_AddTriangleFilled(draw_list, v2(center_x - radius, center_y - radius),
                                 v2(center_x + radius, center_y),
                                 v2(center_x - radius, center_y + radius), 0xFF00D0FFu);
}

/* Filled when enabled, hollow when disabled. */
/* Hollow arrow: the selected caller frame (return address). */
void app_draw_frame_arrow(ImVec2 min, float h)
{
    ImDrawList *draw_list;
    float       center_x;
    float       center_y;
    float       radius;

    draw_list = igGetWindowDrawList();
    center_x = min.x + h * 0.5f;
    center_y = min.y + h * 0.5f;
    radius = h * 0.3f;
    ImDrawList_AddTriangle(draw_list, v2(center_x - radius, center_y - radius),
                           v2(center_x + radius, center_y),
                           v2(center_x - radius, center_y + radius), COL_FRAME, 1.5f);
}

void app_draw_bp_dot(ImVec2 min, float h, bool enabled)
{
    ImDrawList *draw_list;
    ImVec2      center;

    draw_list = igGetWindowDrawList();
    center = v2(min.x + h * 0.5f, min.y + h * 0.5f);
    if (enabled)
        ImDrawList_AddCircleFilled(draw_list, center, h * 0.32f, COL_BP, 0);
    else
        ImDrawList_AddCircle(draw_list, center, h * 0.32f, COL_BP, 0, 1.5f);
}

void app_exec(app_state *app, const char *line)
{
    if (!strcmp(line, "clear")) {
        app->log_first = app->log_count = 0;
        app->log_has_sel = false;
        return;
    }
    if (!app->dbg)
        return;
    dbg_exec(app->dbg, line);
    app->eval_dirty = true;
    if (app->stop_pending)
        handle_stop(app);
}

/* --- shortcuts, menu and toolbar ----------------------------------------------------- */

static bool is_stopped(const app_state *app)
{
    return app->dbg && dbg_get_state(app->dbg) == DBG_STATE_STOPPED;
}

static bool is_running(const app_state *app)
{
    return app->dbg && dbg_get_state(app->dbg) == DBG_STATE_RUNNING;
}

static void connect_or_disconnect(app_state *app)
{
    char line[160];

    if (app->dbg && dbg_get_state(app->dbg) != DBG_STATE_DISCONNECTED) {
        app_exec(app, ".disconnect");
    } else {
        snprintf(line, sizeof line, ".connect %s", app->target_addr);
        app_exec(app, line);
    }
}

/* Seconds a step key must be held before it repeats; after that it steps once per frame,
 * so every step is drawn and the user sees where to let go. */
#define STEP_REPEAT_DELAY 0.25f

static bool step_key(ImGuiKey key)
{
    ImGuiKeyData *data;

    data = igGetKeyData_Key(key);
    if (!data || !data->Down)
        return false;
    return data->DownDuration == 0.0f || data->DownDuration >= STEP_REPEAT_DELAY;
}

/* x64dbg (F7 / F8) and Visual Studio / WinDbg (F11 / F10 / Shift+F11) key bindings. They
 * also work while a text field has focus: F keys type nothing. */
static void handle_shortcuts(app_state *app)
{
    bool shift;

    shift = igGetIO_Nil()->KeyShift;
    if (igIsKeyChordPressed_Nil(ImGuiKey_F9) && is_stopped(app))
        app_exec(app, "g");
    if (igIsKeyChordPressed_Nil(ImGuiKey_F12) && is_running(app))
        app_exec(app, "pause");
    if (igIsKeyChordPressed_Nil(ImGuiMod_Shift | ImGuiKey_F11) && is_stopped(app))
        app_exec(app, "gu");
    else if (!shift && (step_key(ImGuiKey_F7) || step_key(ImGuiKey_F11)) && is_stopped(app))
        app_exec(app, "t");
    else if (!shift && (step_key(ImGuiKey_F8) || step_key(ImGuiKey_F10)) && is_stopped(app))
        app_exec(app, "p");
}

static void main_menu(app_state *app)
{
    bool connected = app->dbg && dbg_get_state(app->dbg) != DBG_STATE_DISCONNECTED;

    if (!igBeginMainMenuBar())
        return;

    if (igBeginMenu("File", true)) {
        if (igMenuItem_Bool(connected ? "Disconnect" : "Connect", NULL, false, app->dbg != NULL))
            connect_or_disconnect(app);
        igSeparator();
        if (igMenuItem_Bool("Folders (symbols, sources, executables)...", NULL, false, app->dbg != NULL))
            app->open_paths = true;
        igSeparator();
        if (igMenuItem_Bool("Exit", "Alt+F4", false, true))
            app->quit = true;
        igEndMenu();
    }
    if (igBeginMenu("View", true)) {
        igMenuItem_BoolPtr(WIN_DISASM, NULL, &app->show_disasm, true);
        igMenuItem_BoolPtr(WIN_SOURCE, NULL, &app->show_source, true);
        igMenuItem_BoolPtr(WIN_REGS,   NULL, &app->show_regs,   true);
        igMenuItem_BoolPtr(WIN_JIT,    NULL, &app->show_jit,    true);
        igMenuItem_BoolPtr(WIN_CMD,    NULL, &app->show_cmd,    true);
        igMenuItem_BoolPtr(WIN_LOCALS, NULL, &app->show_locals, true);
        igMenuItem_BoolPtr(WIN_WATCH,  NULL, &app->show_watch,  true);
        igMenuItem_BoolPtr(WIN_STACK,  NULL, &app->show_stack,  true);
        igSeparator();
        if (igMenuItem_Bool("Reset layout", NULL, false, true))
            app->reset_layout = true;
        igMenuItem_BoolPtr("ImGui demo", NULL, &app->show_demo, true);
        igEndMenu();
    }
    if (igBeginMenu("Debug", true)) {
        if (igMenuItem_Bool("Run", "F9", false, is_stopped(app)))
            app_exec(app, "g");
        if (igMenuItem_Bool("Pause", "F12", false, is_running(app)))
            app_exec(app, "pause");
        igSeparator();
        if (igMenuItem_Bool("Step into", "F7 / F11", false, is_stopped(app)))
            app_exec(app, "t");
        if (igMenuItem_Bool("Step over", "F8 / F10", false, is_stopped(app)))
            app_exec(app, "p");
        if (igMenuItem_Bool("Step out", "Shift+F11", false, is_stopped(app)))
            app_exec(app, "gu");
        if (igMenuItem_Bool("Step to next call", NULL, false, is_stopped(app)))
            app_exec(app, "pc");
        if (igMenuItem_Bool("Step to next branch", NULL, false, is_stopped(app)))
            app_exec(app, "ph");
        igSeparator();
        if (igMenuItem_Bool("Step by source line", NULL,
                            app->dbg && dbg_get_source_step(app->dbg), app->dbg != NULL))
            app_exec(app, dbg_get_source_step(app->dbg) ? "l-t" : "l+t");
        igEndMenu();
    }
    igEndMainMenuBar();
}

static const char *reason_name(em_stop_reason r)
{
    switch (r) {
    case EM_STOP_ATTACH:     return "attached";
    case EM_STOP_PAUSE:      return "paused";
    case EM_STOP_STEP:       return "step";
    case EM_STOP_BREAKPOINT: return "breakpoint";
    case EM_STOP_WATCH:      return "watchpoint";
    case EM_STOP_EXCEPTION:  return "exception";
    case EM_STOP_RESET:      return "reset";
    }
    return "?";
}

static void toolbar_contents(app_state *app)
{
    const em_hello_rep *target = app->dbg ? dbg_target(app->dbg) : NULL;
    const em_x86_regs  *regs = app->dbg ? dbg_regs(app->dbg) : NULL;
    bool                connected = target != NULL;
    char                symbol[160];
    bool                source_mode;

    igSetNextItemWidth(igGetFontSize() * 11);
    igBeginDisabled(connected);
    if (igInputText("##target", app->target_addr, sizeof app->target_addr,
                    ImGuiInputTextFlags_EnterReturnsTrue, NULL, NULL))
        connect_or_disconnect(app);
    igEndDisabled();
    igSameLine(0, -1);
    if (igButton(connected ? "Disconnect" : "Connect", v2(0, 0)))
        connect_or_disconnect(app);
    igSameLine(0, -1);
    igSeparatorEx(ImGuiSeparatorFlags_Vertical, 1.0f);
    igSameLine(0, -1);

    igBeginDisabled(!is_stopped(app));
    if (igButton("Run", v2(0, 0)))
        app_exec(app, "g");
    igSameLine(0, -1);
    igEndDisabled();

    igBeginDisabled(!is_running(app));
    if (igButton("Pause", v2(0, 0)))
        app_exec(app, "pause");
    igSameLine(0, -1);
    igEndDisabled();

    igBeginDisabled(!is_stopped(app));
    if (igButton("Step into", v2(0, 0)))
        app_exec(app, "t");
    igSameLine(0, -1);
    if (igButton("Step over", v2(0, 0)))
        app_exec(app, "p");
    igSameLine(0, -1);
    if (igButton("Step out", v2(0, 0)))
        app_exec(app, "gu");
    igSameLine(0, -1);
    igEndDisabled();

    /* Step mode: F10 / F11 / t / p step by source line or by instruction. */
    source_mode = app->dbg && dbg_get_source_step(app->dbg);
    if (source_mode)
        igPushStyleColor_U32(ImGuiCol_Button, igGetColorU32_Col(ImGuiCol_ButtonActive, 1.0f));
    if (igButton(source_mode ? "Source" : "Asm", v2(igGetFontSize() * 4, 0)) && app->dbg)
        app_exec(app, source_mode ? "l-t" : "l+t");
    if (source_mode)
        igPopStyleColor(1);
    if (igIsItemHovered(0))
        igSetTooltip("Steps go by %s. Click to switch.", source_mode ? "source line" : "instruction");
    igSameLine(0, -1);

    igSeparatorEx(ImGuiSeparatorFlags_Vertical, 1.0f);
    igSameLine(0, -1);
    igAlignTextToFramePadding();
    if (!connected)
        igTextDisabled("Not connected");
    else if (regs && dbg_sym_format(app->dbg, dbg_pc(app->dbg), symbol, sizeof symbol))
        igText("%s: stopped (%s) at %016" PRIx64 " %s", target->target,
               reason_name(app->last_reason), regs->core.rip, symbol);
    else if (regs)
        igText("%s: stopped (%s) at %016" PRIx64, target->target, reason_name(app->last_reason),
               regs->core.rip);
    else
        igText("%s: running", target->target);
}

/* --- dockspace ----------------------------------------------------------------------- */

/* The JIT node is always part of the layout. While the JIT pane is closed
 * the node is empty and hidden, and Disassembly/Source take its space. */
static void build_default_layout(ImGuiID dockspace, ImVec2 size)
{
    ImGuiID top, bottom, right, center, code, jit, disasm, source, regs, vars, stack;

    igDockBuilderRemoveNode(dockspace);
    igDockBuilderAddNode(dockspace, ImGuiDockNodeFlags_DockSpace);
    igDockBuilderSetNodeSize(dockspace, size);

    igDockBuilderSplitNode(dockspace, ImGuiDir_Down,  0.22f, &bottom, &top);
    igDockBuilderSplitNode(top,       ImGuiDir_Right, 0.24f, &right,  &center);
    igDockBuilderSplitNode(center,    ImGuiDir_Down,  0.40f, &jit,    &code);
    igDockBuilderSplitNode(code,      ImGuiDir_Right, 0.50f, &source, &disasm);
    igDockBuilderSplitNode(right,     ImGuiDir_Down,  0.50f, &vars,   &regs);
    igDockBuilderSplitNode(bottom,    ImGuiDir_Right, 0.40f, &stack,  &bottom);

    igDockBuilderDockWindow(WIN_DISASM, disasm);
    igDockBuilderDockWindow(WIN_SOURCE, source);
    igDockBuilderDockWindow(WIN_JIT,    jit);
    igDockBuilderDockWindow(WIN_REGS,   regs);
    igDockBuilderDockWindow(WIN_LOCALS, vars);
    igDockBuilderDockWindow(WIN_WATCH,  vars);
    igDockBuilderDockWindow(WIN_STACK,  stack);
    igDockBuilderDockWindow(WIN_CMD,    bottom);
    igDockBuilderFinish(dockspace);
}

static void host_windows(app_state *app)
{
    const ImGuiViewport *vp    = igGetMainViewport();
    ImGuiStyle          *style = igGetStyle();
    float                bar_h = igGetFrameHeight() + style->WindowPadding.y * 2.0f;
    ImVec2               dock_pos  = v2(vp->WorkPos.x, vp->WorkPos.y + bar_h);
    ImVec2               dock_size = v2(vp->WorkSize.x, vp->WorkSize.y - bar_h);
    ImGuiWindowFlags     fixed = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                                 ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings |
                                 ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus |
                                 ImGuiWindowFlags_NoNavFocus;
    ImGuiID              dockspace;

    igSetNextWindowPos(vp->WorkPos, ImGuiCond_Always, v2(0, 0));
    igSetNextWindowSize(v2(vp->WorkSize.x, bar_h), ImGuiCond_Always);
    igSetNextWindowViewport(vp->ID);
    igBegin("##toolbar", NULL, fixed);
    toolbar_contents(app);
    igEnd();

    igSetNextWindowPos(dock_pos, ImGuiCond_Always, v2(0, 0));
    igSetNextWindowSize(dock_size, ImGuiCond_Always);
    igSetNextWindowViewport(vp->ID);
    igPushStyleVar_Vec2(ImGuiStyleVar_WindowPadding, v2(0, 0));
    igPushStyleVar_Float(ImGuiStyleVar_WindowBorderSize, 0);
    igBegin("##dockhost", NULL, fixed);
    igPopStyleVar(2);

    dockspace = igGetID_Str("main_dockspace");   /* scoped to ##dockhost */
    if (app->reset_layout || igDockBuilderGetNode(dockspace) == NULL) {
        build_default_layout(dockspace, dock_size);
        app->reset_layout = false;
    }
    igDockSpace(dockspace, v2(0, 0), ImGuiDockNodeFlags_None, NULL);
    igEnd();
}

void app_frame(app_state *app)
{
    if (app->dbg)
        dbg_poll(app->dbg);
    if (app->stop_pending)
        handle_stop(app);
    settings_sync(app);
    if (app->eval_dirty)
        eval_refresh(app);
    follow_frame(app);

    handle_shortcuts(app);

    main_menu(app);
    host_windows(app);
    paths_dialog(app);

    pane_disasm(app);
    pane_source(app);
    pane_jit(app);
    pane_registers(app);
    pane_command(app);
    pane_locals(app);
    pane_watch(app);
    pane_stack(app);

    if (app->show_demo)
        igShowDemoWindow(&app->show_demo);
}
