/* Symbol, source and executable folders: saved in imgui.ini as [emdbg][Paths], and the
 * dialog that edits them. Folders typed with .sympath / .srcpath / .exepath are saved too. */
#include "app.h"

#include <stdio.h>
#include <string.h>

#define PATHS_POPUP "Folders"

static void *paths_open(ImGuiContext *ctx, ImGuiSettingsHandler *handler, const char *name)
{
    (void)ctx;
    return strcmp(name, "Paths") == 0 ? handler->UserData : NULL;
}

static void paths_read_line(ImGuiContext *ctx, ImGuiSettingsHandler *handler, void *entry,
                            const char *line)
{
    app_state *app;

    (void)ctx;
    (void)handler;
    app = (app_state *)entry;
    if (!strncmp(line, "SymPath=", 8))
        snprintf(app->sym_path, sizeof app->sym_path, "%s", line + 8);
    else if (!strncmp(line, "SrcPath=", 8))
        snprintf(app->src_path, sizeof app->src_path, "%s", line + 8);
    else if (!strncmp(line, "ExePath=", 8))
        snprintf(app->exe_path, sizeof app->exe_path, "%s", line + 8);
    else if (!strncmp(line, "Watch=", 6) && line[6] && app->watch_count < APP_WATCHES)
        snprintf(app->watch_exprs[app->watch_count++], APP_EXPR_SIZE, "%s", line + 6);
}

/* Runs after imgui.ini is read on the first frame. */
static void paths_apply(ImGuiContext *ctx, ImGuiSettingsHandler *handler)
{
    app_state *app;

    (void)ctx;
    app = (app_state *)handler->UserData;
    if (!app->dbg)
        return;
    dbg_set_sym_path(app->dbg, app->sym_path);
    dbg_set_src_path(app->dbg, app->src_path);
    dbg_set_exe_path(app->dbg, app->exe_path);
}

static void paths_write(ImGuiContext *ctx, ImGuiSettingsHandler *handler, ImGuiTextBuffer *out)
{
    app_state *app;
    int        index;

    (void)ctx;
    app = (app_state *)handler->UserData;
    ImGuiTextBuffer_appendf(out, "[%s][Paths]\n", handler->TypeName);
    ImGuiTextBuffer_appendf(out, "SymPath=%s\n", app->sym_path);
    ImGuiTextBuffer_appendf(out, "SrcPath=%s\n", app->src_path);
    ImGuiTextBuffer_appendf(out, "ExePath=%s\n", app->exe_path);
    for (index = 0; index < app->watch_count; index++)
        ImGuiTextBuffer_appendf(out, "Watch=%s\n", app->watch_exprs[index]);
    ImGuiTextBuffer_appendf(out, "\n");
}

/* Call after igCreateContext and before the first frame, which reads imgui.ini. */
void settings_register(app_state *app)
{
    ImGuiSettingsHandler handler;

    memset(&handler, 0, sizeof handler);
    handler.TypeName   = "emdbg";
    handler.TypeHash   = igImHashStr("emdbg", 0, 0);
    handler.ReadOpenFn = paths_open;
    handler.ReadLineFn = paths_read_line;
    handler.ApplyAllFn = paths_apply;
    handler.WriteAllFn = paths_write;
    handler.UserData   = app;
    igAddSettingsHandler(&handler);
}

/* Picks up folders changed through dbgeng (commands or the dialog) and saves them. */
void settings_sync(app_state *app)
{
    const char *sym;
    const char *src;
    const char *exe;

    if (!app->dbg)
        return;
    sym = dbg_get_sym_path(app->dbg);
    src = dbg_get_src_path(app->dbg);
    exe = dbg_get_exe_path(app->dbg);
    if (!strcmp(sym, app->sym_path) && !strcmp(src, app->src_path) &&
        !strcmp(exe, app->exe_path))
        return;
    snprintf(app->sym_path, sizeof app->sym_path, "%s", sym);
    snprintf(app->src_path, sizeof app->src_path, "%s", src);
    snprintf(app->exe_path, sizeof app->exe_path, "%s", exe);
    app->src_refresh = true;
    igMarkIniSettingsDirty_Nil();
}

void paths_dialog(app_state *app)
{
    float button_width;

    button_width = igGetFontSize() * 6;
    if (app->open_paths) {
        snprintf(app->edit_sym_path, sizeof app->edit_sym_path, "%s", app->sym_path);
        snprintf(app->edit_src_path, sizeof app->edit_src_path, "%s", app->src_path);
        snprintf(app->edit_exe_path, sizeof app->edit_exe_path, "%s", app->exe_path);
        igOpenPopup_Str(PATHS_POPUP, 0);
        app->open_paths = false;
    }
    igSetNextWindowSize(v2(igGetFontSize() * 44, 0), ImGuiCond_Appearing);
    if (!igBeginPopupModal(PATHS_POPUP, NULL, 0))
        return;

    igTextWrapped("Separate folders with ';'.");
    igSpacing();
    igTextUnformatted("Symbol folders", NULL);
    igTextDisabled("searched for .ids / .pdb files (lds)");
    igSetNextItemWidth(-1);
    igInputText("##sym", app->edit_sym_path, sizeof app->edit_sym_path, 0, NULL, NULL);
    igSpacing();
    igTextUnformatted("Source folders", NULL);
    igTextDisabled("used when a source path recorded in the symbols does not exist");
    igSetNextItemWidth(-1);
    igInputText("##src", app->edit_src_path, sizeof app->edit_src_path, 0, NULL, NULL);
    igSpacing();
    igTextUnformatted("Executable folders", NULL);
    igTextDisabled("module images (.efi .dll .exe .sys) for lds <file> <start> <end> and find");
    igSetNextItemWidth(-1);
    igInputText("##exe", app->edit_exe_path, sizeof app->edit_exe_path, 0, NULL, NULL);
    igSpacing();

    if (igButton("OK", v2(button_width, 0)) && app->dbg) {
        dbg_set_sym_path(app->dbg, app->edit_sym_path);
        dbg_set_src_path(app->dbg, app->edit_src_path);
        dbg_set_exe_path(app->dbg, app->edit_exe_path);
        settings_sync(app);
        igCloseCurrentPopup();
    }
    igSetItemDefaultFocus();
    igSameLine(0, -1);
    if (igButton("Cancel", v2(button_width, 0)) || igIsKeyChordPressed_Nil(ImGuiKey_Escape))
        igCloseCurrentPopup();
    igEndPopup();
}
