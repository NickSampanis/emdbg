/* Locals and Watch panes: trees of evaluated expressions (dbg_locals, dbg_eval,
 * dbg_eval_children). Evaluating reads target memory, so rows are cached in
 * app->eval_nodes and evaluated again only after eval_refresh (each stop and command).
 * A row's ImGui ID is its expression, so expanded rows stay expanded across stops. */
#include "app.h"

#include <stdio.h>
#include <string.h>

void eval_refresh(app_state *app)
{
    int index;

    app->eval_dirty = false;
    app->eval_node_count = 0;
    for (index = 0; index < APP_WATCHES; index++)
        app->watch_roots[index] = -1;
    app->local_count = 0;
    app->locals_loaded = false;
    app->locals_message[0] = '\0';
    app->stack_loaded = false;
}

void watch_add(app_state *app, const char *expr)
{
    while (*expr == ' ')
        expr++;
    if (!*expr || app->watch_count >= APP_WATCHES)
        return;
    snprintf(app->watch_exprs[app->watch_count], APP_EXPR_SIZE, "%s", expr);
    app->watch_roots[app->watch_count] = -1;
    app->watch_count++;
    igMarkIniSettingsDirty_Nil();
}

static void watch_remove(app_state *app, int index)
{
    if (index < 0 || index >= app->watch_count)
        return;
    memmove(app->watch_exprs[index], app->watch_exprs[index + 1],
            (size_t)(app->watch_count - index - 1) * sizeof app->watch_exprs[0]);
    app->watch_count--;
    app->eval_dirty = true;
    igMarkIniSettingsDirty_Nil();
}

static int node_new(app_state *app, const char *name, const char *expr)
{
    eval_node *node;

    if (app->eval_node_count >= APP_EVAL_NODES)
        return -1;
    node = &app->eval_nodes[app->eval_node_count];
    memset(node, 0, sizeof *node);
    snprintf(node->name, sizeof node->name, "%s", name);
    snprintf(node->expr, sizeof node->expr, "%s", expr);
    return app->eval_node_count++;
}

static void node_fill(eval_node *node, const dbg_eval_result *result, bool ok)
{
    snprintf(node->type, sizeof node->type, "%s", result->type);
    snprintf(node->value, sizeof node->value, "%s", result->value);
    node->expandable = ok && result->expandable;
    node->ok = ok;
}

static int node_eval(app_state *app, const char *expr)
{
    dbg_eval_result result;
    int             index;
    bool            ok;

    index = node_new(app, expr, expr);
    if (index < 0)
        return -1;
    ok = dbg_eval(app->dbg, expr, &result) == DBG_OK;
    node_fill(&app->eval_nodes[index], &result, ok);
    return index;
}

static void add_child(void *user, const dbg_eval_child *child)
{
    app_state *app;
    int        index;

    app = (app_state *)user;
    index = node_new(app, child->name, child->expr);
    if (index >= 0)
        node_fill(&app->eval_nodes[index], child->result, true);
}

static void load_children(app_state *app, int index)
{
    dbg_eval_result failure;
    int             first;
    int             error_index;

    first = app->eval_node_count;
    app->eval_nodes[index].children_loaded = true;
    if (dbg_eval_children(app->dbg, app->eval_nodes[index].expr, add_child, app) != DBG_OK) {
        app->eval_node_count = first;
        error_index = node_new(app, "", "");
        if (error_index >= 0) {
            memset(&failure, 0, sizeof failure);
            snprintf(failure.value, sizeof failure.value, "<cannot read>");
            node_fill(&app->eval_nodes[error_index], &failure, false);
        }
    }
    app->eval_nodes[index].first_child = first;
    app->eval_nodes[index].child_count = app->eval_node_count - first;
}

/* Right-click menu of a row. watch_index >= 0 for top-level Watch rows. */
static void node_menu(app_state *app, int index, int watch_index)
{
    eval_node *node;

    if (!igBeginPopupContextItem(NULL, ImGuiPopupFlags_MouseButtonRight))
        return;
    node = &app->eval_nodes[index];
    if (igMenuItem_Bool("Copy value", NULL, false, true))
        igSetClipboardText(node->value);
    if (igMenuItem_Bool("Copy expression", NULL, false, node->expr[0] != '\0'))
        igSetClipboardText(node->expr);
    if (watch_index < 0 && igMenuItem_Bool("Add to watch", NULL, false, node->expr[0] != '\0'))
        watch_add(app, node->expr);
    if (watch_index >= 0) {
        if (igMenuItem_Bool("Edit", NULL, false, true)) {
            snprintf(app->watch_input, sizeof app->watch_input, "%s",
                     app->watch_exprs[watch_index]);
            app->watch_edit = watch_index;
            app->watch_focus_input = true;
        }
        if (igMenuItem_Bool("Remove", "Del", false, true))
            watch_remove(app, watch_index);
    }
    igEndPopup();
}

static void draw_node(app_state *app, int index, int watch_index, bool param)
{
    eval_node         *node;
    ImGuiTreeNodeFlags flags;
    bool               open;
    int                child;

    node = &app->eval_nodes[index];
    igTableNextRow(0, 0);
    igTableSetColumnIndex(0);
    flags = ImGuiTreeNodeFlags_SpanFullWidth | ImGuiTreeNodeFlags_OpenOnArrow |
            ImGuiTreeNodeFlags_OpenOnDoubleClick;
    if (!node->expandable)
        flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
    if (param)
        igPushStyleColor_U32(ImGuiCol_Text, COL_HEADER);
    open = igTreeNodeEx_StrStr(node->expr[0] ? node->expr : "##error", flags, "%s", node->name);
    if (param)
        igPopStyleColor(1);
    node_menu(app, index, watch_index);
    if (watch_index >= 0 && igIsItemFocused() && igIsKeyPressed_Bool(ImGuiKey_Delete, false))
        watch_remove(app, watch_index);

    igTableSetColumnIndex(1);
    node = &app->eval_nodes[index];
    if (node->ok)
        igTextUnformatted(node->value, NULL);
    else
        text_col(COL_ERROR, node->value);
    igTableSetColumnIndex(2);
    text_col(COL_DIM, node->type);

    if (!open || !node->expandable)
        return;
    if (!node->children_loaded)
        load_children(app, index);
    node = &app->eval_nodes[index];
    for (child = 0; child < node->child_count; child++)
        draw_node(app, node->first_child + child, -1, false);
    if (app->eval_node_count >= APP_EVAL_NODES) {
        igTableNextRow(0, 0);
        igTableSetColumnIndex(0);
        igTextDisabled("(too many rows; collapse something)");
    }
    igTreePop();
}

static bool begin_tree_table(const char *id, float height)
{
    ImGuiTableFlags flags;

    flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_BordersInnerV;
    if (!igBeginTable(id, 3, flags, v2(0, height), 0))
        return false;
    igTableSetupScrollFreeze(0, 1);
    igTableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.35f, 0);
    igTableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.45f, 0);
    igTableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 0.20f, 0);
    igTableHeadersRow();
    return true;
}

/* Shown instead of values while nothing can be evaluated. */
static bool target_unavailable(app_state *app)
{
    if (!app->dbg || dbg_get_state(app->dbg) == DBG_STATE_DISCONNECTED) {
        igTextDisabled("Not connected.");
        return true;
    }
    if (dbg_get_state(app->dbg) == DBG_STATE_RUNNING) {
        igTextDisabled("Target is running.");
        return true;
    }
    return false;
}

/* --- Locals ------------------------------------------------------------------------- */

static void add_local(void *user, const dbg_local *local)
{
    app_state       *app;
    dbg_eval_result  result;
    int              index;

    app = (app_state *)user;
    if (app->local_count >= APP_LOCALS)
        return;
    index = node_new(app, local->name, local->name);
    if (index < 0)
        return;
    snprintf(result.type, sizeof result.type, "%s", local->type);
    snprintf(result.value, sizeof result.value, "%s", local->value);
    result.expandable = local->expandable;
    node_fill(&app->eval_nodes[index], &result, local->value[0] != '<');
    app->local_roots[app->local_count] = index;
    app->local_params[app->local_count] = local->is_param;
    app->local_count++;
}

static void load_locals(app_state *app)
{
    dbg_status status;

    app->locals_loaded = true;
    status = dbg_locals(app->dbg, add_local, app);
    if (status == DBG_E_BADARG)
        snprintf(app->locals_message, sizeof app->locals_message,
                 "No function symbols at the pc (load them with lds).");
    else if (status != DBG_OK)
        snprintf(app->locals_message, sizeof app->locals_message, "%s", dbg_status_str(status));
    else if (!app->local_count)
        snprintf(app->locals_message, sizeof app->locals_message, "No locals in this function.");
}

void pane_locals(app_state *app)
{
    dbg_frame frame;
    char      symbol[160];
    char      header[192];
    int       index;

    if (!app->show_locals)
        return;
    if (!igBegin(WIN_LOCALS, &app->show_locals, 0)) {
        igEnd();
        return;
    }
    if (target_unavailable(app)) {
        igEnd();
        return;
    }
    if (!app->locals_loaded)
        load_locals(app);
    if (dbg_frame_info(app->dbg, &frame) == DBG_OK &&
        dbg_sym_format(app->dbg, frame.pc, symbol, sizeof symbol)) {
        if (frame.number) {
            snprintf(header, sizeof header, "frame %02x: %s", frame.number, symbol);
            text_col(COL_FRAME, header);
        } else {
            text_col(COL_HEADER, symbol);
        }
    }
    if (app->locals_message[0]) {
        igTextDisabled("%s", app->locals_message);
    } else if (begin_tree_table("locals", 0)) {
        for (index = 0; index < app->local_count; index++)
            draw_node(app, app->local_roots[index], -1, app->local_params[index]);
        igEndTable();
    }
    igEnd();
}

/* --- Watch -------------------------------------------------------------------------- */

static void watch_input(app_state *app)
{
    ImGuiInputTextFlags flags;
    const char         *hint;

    flags = ImGuiInputTextFlags_EnterReturnsTrue;
    hint = app->watch_edit >= 0 ? "edit the expression (Enter)" : "add an expression (Enter)";
    igSetNextItemWidth(-1);
    if (app->watch_focus_input) {
        igSetKeyboardFocusHere(0);
        app->watch_focus_input = false;
    }
    if (!igInputTextWithHint("##watch_add", hint, app->watch_input, sizeof app->watch_input,
                             flags, NULL, NULL))
        return;
    if (app->watch_edit >= 0 && app->watch_edit < app->watch_count) {
        if (app->watch_input[0]) {
            snprintf(app->watch_exprs[app->watch_edit], APP_EXPR_SIZE, "%s", app->watch_input);
            app->eval_dirty = true;
            igMarkIniSettingsDirty_Nil();
        } else {
            watch_remove(app, app->watch_edit);
        }
    } else {
        watch_add(app, app->watch_input);
    }
    app->watch_edit = -1;
    app->watch_input[0] = '\0';
    app->watch_focus_input = true;
}

void pane_watch(app_state *app)
{
    bool stopped;
    int  index;

    if (!app->show_watch)
        return;
    if (!igBegin(WIN_WATCH, &app->show_watch, 0)) {
        igEnd();
        return;
    }
    stopped = app->dbg && dbg_get_state(app->dbg) == DBG_STATE_STOPPED;
    if (begin_tree_table("watch", -igGetFrameHeightWithSpacing())) {
        for (index = 0; index < app->watch_count; index++) {
            if (!stopped) {
                igTableNextRow(0, 0);
                igTableSetColumnIndex(0);
                igTextUnformatted(app->watch_exprs[index], NULL);
                igTableSetColumnIndex(1);
                igTextDisabled(app->dbg && dbg_get_state(app->dbg) == DBG_STATE_RUNNING
                                   ? "(running)" : "(not connected)");
                continue;
            }
            if (app->watch_roots[index] < 0)
                app->watch_roots[index] = node_eval(app, app->watch_exprs[index]);
            if (app->watch_roots[index] >= 0)
                draw_node(app, app->watch_roots[index], index, false);
        }
        igEndTable();
    }
    watch_input(app);
    igEnd();
}
