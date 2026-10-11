#ifndef EMDBG_GUI_APP_H
#define EMDBG_GUI_APP_H

#include <stdbool.h>
#include <stdint.h>

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"

#include "emdbg/dbgeng.h"

/* Window titles are also ImGui IDs and imgui.ini keys: renaming one loses
 * its saved dock position. */
#define WIN_DISASM "Disassembly"
#define WIN_SOURCE "Source"
#define WIN_REGS   "Registers"
#define WIN_JIT    "JIT"
#define WIN_CMD    "Command"
#define WIN_LOCALS "Locals"
#define WIN_WATCH  "Watch"
#define WIN_STACK  "Call Stack"

/* Bits for app_state.scroll_mask: panes that should scroll the current
 * selection into view on their next draw. */
enum {
    PANE_DISASM = 1 << 0,
    PANE_SOURCE = 1 << 1,
    PANE_JIT    = 1 << 2,
    PANE_ALL    = PANE_DISASM | PANE_SOURCE | PANE_JIT,
};

#define APP_LOG_LINES     2048
#define APP_LOG_LINE_SIZE 256
#define APP_CODE_INSNS    64      /* instructions fetched at a time for the disassembly pane */
#define APP_CODE_MAX      8192    /* instructions kept; scrolling down fetches more up to this */
#define APP_HISTORY       128     /* commands remembered for Up / Down */
#define APP_PATH_SIZE     1024
#define APP_WATCHES       64      /* expressions in the Watch pane */
#define APP_LOCALS        128     /* locals shown in the Locals pane */
#define APP_EXPR_SIZE     256
#define APP_EVAL_NODES    2048    /* evaluated rows of both panes, refilled after each stop */
#define APP_FRAMES        256     /* frames shown in the Call Stack pane */

/* One evaluated row of the Locals / Watch trees. Children are loaded when the row is
 * first expanded and stay until the next refresh. */
typedef struct eval_node {
    char     name[64];
    char     expr[APP_EXPR_SIZE];
    char     type[128];
    char     value[256];
    bool     ok;
    bool     expandable;
    bool     children_loaded;
    int      first_child;
    int      child_count;
} eval_node;

typedef struct app_state {
    bool show_disasm;
    bool show_source;
    bool show_regs;
    bool show_jit;
    bool show_cmd;
    bool show_locals;
    bool show_watch;
    bool show_stack;
    bool show_demo;
    bool reset_layout;
    bool quit;

    dbg_ctx    *dbg;
    char        target_addr[128];  /* host:port for the Connect button */

    uint64_t    selected;          /* address shared by disasm, source and JIT */
    unsigned    scroll_mask;

    /* Set by the dbgeng event callback; handled in app_frame, because the GUI must
     * not call dbgeng from inside a callback. */
    bool        stop_pending;
    em_stop_reason last_reason;

    /* Registers at the last two stops, to highlight what the last step changed. */
    em_x86_regs last_regs;
    em_x86_regs prev_regs;
    bool        have_last;
    bool        have_prev;

    /* Instructions from pc onwards, refreshed on every stop. */
    uint64_t    code_addr;
    dbg_insn   *code;              /* APP_CODE_MAX entries, allocated in app_init */
    uint32_t    code_len;
    bool        code_end;          /* nothing more can be decoded after the last one */

    int         sel_reg;           /* selected row in the registers pane, -1 = none */

    char         cmd_input[256];
    char         history[APP_HISTORY][256];   /* typed commands, ring buffer */
    int          hist_first;
    int          hist_count;
    int          hist_pos;         /* entry shown by Up/Down, -1 = new line */
    char         log[APP_LOG_LINES][APP_LOG_LINE_SIZE];
    dbg_out_kind log_kind[APP_LOG_LINES];
    int          log_first;        /* ring buffer start */
    int          log_count;
    bool         log_scroll;
    uint64_t     log_total;        /* lines ever logged; numbers lines across the ring */
    uint64_t     log_sel_anchor;   /* selected lines, as log_total numbers */
    uint64_t     log_sel_end;
    bool         log_has_sel;
    bool         log_dragging;

    /* Symbol and source folders, saved in imgui.ini as [emdbg][Paths]. The edit_ copies
     * belong to the folders dialog. */
    char         sym_path[APP_PATH_SIZE];
    char         src_path[APP_PATH_SIZE];
    char         exe_path[APP_PATH_SIZE];
    char         edit_sym_path[APP_PATH_SIZE];
    char         edit_src_path[APP_PATH_SIZE];
    char         edit_exe_path[APP_PATH_SIZE];
    bool         open_paths;       /* open the folders dialog on the next frame */

    /* Source pane: the shown file, split into NUL-terminated lines. */
    char         src_file[APP_PATH_SIZE];   /* path from dbgeng, "" = nothing shown */
    bool         src_found;
    bool         src_refresh;      /* look the selected address up again */
    char        *src_text;
    uint32_t    *src_lines;        /* offset of each line in src_text */
    uint32_t     src_line_count;
    uint32_t     src_sel_line;     /* 1-based, 0 = none */
    uint32_t     src_sel_anchor;   /* other end of a selected range (Shift+click / drag) */
    bool         src_dragging;
    char         src_word[128];    /* identifier under the mouse at the last right-click */
    uint32_t     src_menu_line;    /* line that was right-clicked */
    int          src_module_count; /* dbg_module_count at the last lookup */

    /* Locals and Watch panes. eval_dirty drops every evaluated row (after a stop or a
     * command); rows are evaluated again lazily when drawn. Watch expressions are saved
     * in imgui.ini. */
    char         watch_exprs[APP_WATCHES][APP_EXPR_SIZE];
    int          watch_count;
    int          watch_roots[APP_WATCHES];   /* node index, -1 = not evaluated yet */
    char         watch_input[APP_EXPR_SIZE];
    int          watch_edit;                 /* row being edited, -1 = none */
    bool         watch_focus_input;
    int          local_roots[APP_LOCALS];
    bool         local_params[APP_LOCALS];
    int          local_count;
    bool         locals_loaded;
    char         locals_message[128];
    eval_node    eval_nodes[APP_EVAL_NODES];
    int          eval_node_count;
    bool         eval_dirty;

    /* Call Stack pane, walked again after each refresh. view_frame is the frame the code
     * panes show (dbgeng's selected frame, .frame N); frame_pc is its pc, the return
     * address for caller frames. */
    dbg_frame    stack_frames[APP_FRAMES];
    char         stack_sites[APP_FRAMES][160];
    int          stack_count;
    bool         stack_loaded;
    uint32_t     view_frame;
    uint64_t     frame_pc;
} app_state;

void app_init(app_state *app);
void app_shutdown(app_state *app);
void app_frame(app_state *app);

/* Append text to the command log; splits on newlines. */
void app_log(app_state *app, dbg_out_kind kind, const char *text);

/* Run a command line through dbgeng (also used by buttons and shortcuts).
 * "clear" is handled by the GUI. */
void app_exec(app_state *app, const char *line);

/* Select an address and scroll every pane except `origin` to it. */
void app_select(app_state *app, uint64_t addr, unsigned origin);

/* Disassembly pane code: decode from addr (replacing what is shown), or append the next
 * APP_CODE_INSNS instructions after the last one. */
void app_code_load(app_state *app, uint64_t addr);
void app_code_more(app_state *app);

/* Set or clear an exec breakpoint through the command line, so it shows in the log. */
void app_toggle_bp(app_state *app, uint64_t addr);

/* Gutter marks for a row starting at `min` with height `h`. */
void app_draw_pc_arrow(ImVec2 min, float h);
void app_draw_frame_arrow(ImVec2 min, float h);
void app_draw_bp_dot(ImVec2 min, float h, bool enabled);

/* settings.c: folders persistence and the folders dialog. */
void settings_register(app_state *app);
void settings_sync(app_state *app);
void paths_dialog(app_state *app);

void source_free(app_state *app);

void pane_disasm(app_state *app);
void pane_source(app_state *app);
void pane_registers(app_state *app);
void pane_jit(app_state *app);
void pane_command(app_state *app);
void pane_locals(app_state *app);
void pane_watch(app_state *app);
void pane_stack(app_state *app);

/* pane_watch.c: Locals / Watch evaluation cache and watch list. */
void eval_refresh(app_state *app);
void watch_add(app_state *app, const char *expr);

/* Shared colors (ABGR). */
#define COL_PC_BG     0x5000B4FFu   /* amber, translucent */
#define COL_FRAME_BG  0x4040C060u   /* green, translucent: selected caller frame */
#define COL_FRAME     0xFF60D060u
#define COL_BP        0xFF3C3CE6u   /* red */
#define COL_BP_BG     0x353C3CE6u
#define COL_ADDR      0xFFB0B0B0u
#define COL_DIM       0xFF808080u
#define COL_CHANGED   0xFF5050FFu   /* register changed */
#define COL_HEADER    0xFFE0C080u
#define COL_ERROR     0xFF6060FFu
#define COL_TARGET    0xFFD0D080u

static inline ImVec2 v2(float x, float y) { ImVec2 v = { x, y }; return v; }

static inline void text_col(ImU32 col, const char *text)
{
    igPushStyleColor_U32(ImGuiCol_Text, col);
    igTextUnformatted(text, NULL);
    igPopStyleColor(1);
}

#endif
