#include "app.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct reg_row {
    const char *name;         /* NULL = section separator */
    uint8_t     block;        /* em_regblock the value lives in */
    uint8_t     size;         /* bytes */
    uint16_t    offset;       /* into em_x86_regs */
} reg_row;

#define CORE(n, f)  { n, EM_RB_X86_CORE, 8, (uint16_t)offsetof(em_x86_regs, core.f) }
#define CTRL(n, f)  { n, EM_RB_X86_CTRL, 8, (uint16_t)offsetof(em_x86_regs, ctrl.f) }
#define SEL(n, f)   { n, EM_RB_X86_SEG,  2, (uint16_t)offsetof(em_x86_regs, seg.f.selector) }
#define BASE(n, f)  { n, EM_RB_X86_SEG,  8, (uint16_t)offsetof(em_x86_regs, seg.f.base) }
#define SECTION     { NULL, 0, 0, 0 }

static const reg_row rows[] = {
    CORE("rax", rax), CORE("rbx", rbx), CORE("rcx", rcx), CORE("rdx", rdx),
    CORE("rsi", rsi), CORE("rdi", rdi), CORE("rbp", rbp), CORE("rsp", rsp),
    CORE("r8", r8),   CORE("r9", r9),   CORE("r10", r10), CORE("r11", r11),
    CORE("r12", r12), CORE("r13", r13), CORE("r14", r14), CORE("r15", r15),
    SECTION,
    CORE("rip", rip), CORE("rflags", rflags),
    SECTION,
    SEL("cs", cs), SEL("ss", ss), SEL("ds", ds), SEL("es", es), SEL("fs", fs), SEL("gs", gs),
    BASE("fs.base", fs), BASE("gs.base", gs),
    SECTION,
    CTRL("cr0", cr0), CTRL("cr2", cr2), CTRL("cr3", cr3), CTRL("cr4", cr4), CTRL("cr8", cr8),
    CTRL("efer", efer),
    CTRL("dr0", dr0), CTRL("dr1", dr1), CTRL("dr2", dr2), CTRL("dr3", dr3),
    CTRL("dr6", dr6), CTRL("dr7", dr7),
};

static uint64_t row_value(const em_x86_regs *r, const reg_row *row)
{
    uint64_t v = 0;

    memcpy(&v, (const uint8_t *)r + row->offset, row->size);
    return v;
}

/* WinDbg-style flag mnemonics: "nv up ei pl zr na pe nc". */
static void flags_text(uint64_t f, char *buf, size_t cap)
{
    snprintf(buf, cap, "%s %s %s %s %s %s %s %s",
             f & (1u << 11) ? "ov" : "nv", f & (1u << 10) ? "dn" : "up",
             f & (1u << 9) ? "ei" : "di",  f & (1u << 7) ? "ng" : "pl",
             f & (1u << 6) ? "zr" : "nz",  f & (1u << 4) ? "ac" : "na",
             f & (1u << 2) ? "pe" : "po",  f & (1u << 0) ? "cy" : "nc");
}

static void format_value(const em_x86_regs *r, const reg_row *row, char *buf, size_t cap)
{
    snprintf(buf, cap, "%0*" PRIx64, row->size * 2, row_value(r, row));
}

/* "rax=0000000000000000\n..." for every register this target reported. */
static void copy_all(const em_x86_regs *r)
{
    char   text[2048];
    char   value[32];
    size_t pos = 0;
    size_t i;

    text[0] = '\0';
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        if (!rows[i].name || !(r->valid & EM_RB_BIT(rows[i].block)))
            continue;
        format_value(r, &rows[i], value, sizeof value);
        pos += (size_t)snprintf(text + pos, sizeof text - pos, "%s=%s\n", rows[i].name, value);
        if (pos >= sizeof text)
            break;
    }
    igSetClipboardText(text);
}

/* Right-click menu of one register row. */
static void row_menu(const em_x86_regs *r, const reg_row *row)
{
    char value[32];
    char line[64];

    if (!igBeginPopupContextItem("ctx", ImGuiPopupFlags_MouseButtonRight))
        return;
    format_value(r, row, value, sizeof value);
    if (igMenuItem_Bool("Copy value", "Ctrl+C", false, true))
        igSetClipboardText(value);
    if (igMenuItem_Bool("Copy name=value", NULL, false, true)) {
        snprintf(line, sizeof line, "%s=%s", row->name, value);
        igSetClipboardText(line);
    }
    igSeparator();
    if (igMenuItem_Bool("Copy all registers", NULL, false, true))
        copy_all(r);
    igEndPopup();
}

void pane_registers(app_state *app)
{
    ImGuiTableFlags    flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit |
                               ImGuiTableFlags_RowBg;
    const em_x86_regs *regs;
    const reg_row     *row;
    uint64_t           v;
    char               value[32];
    size_t             i;

    if (!app->show_regs)
        return;
    if (!igBegin(WIN_REGS, &app->show_regs, 0)) {
        igEnd();
        return;
    }

    regs = app->dbg ? dbg_regs(app->dbg) : NULL;
    if (!regs) {
        igTextDisabled(app->dbg && dbg_get_state(app->dbg) == DBG_STATE_RUNNING
                           ? "Target is running." : "Not connected.");
        igEnd();
        return;
    }

    if (igBeginTable("regs", 2, flags, v2(0, 0), 0)) {
        for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
            row = &rows[i];
            if (!row->name) {
                igTableNextRow(0, 0);
                continue;                        /* empty row between sections */
            }
            if (!(regs->valid & EM_RB_BIT(row->block)))
                continue;

            v = row_value(regs, row);
            format_value(regs, row, value, sizeof value);
            igTableNextRow(0, 0);
            igTableSetColumnIndex(0);
            igPushID_Int((int)i);
            if (igSelectable_Bool("##sel", app->sel_reg == (int)i,
                                  ImGuiSelectableFlags_SpanAllColumns, v2(0, 0)))
                app->sel_reg = (int)i;
            if (igIsItemHovered(0) && igIsMouseClicked_Bool(ImGuiMouseButton_Right, false))
                app->sel_reg = (int)i;
            row_menu(regs, row);
            igPopID();
            igSameLine(0, 0);
            text_col(COL_HEADER, row->name);
            igTableSetColumnIndex(1);
            if (app->have_prev && v != row_value(&app->prev_regs, row))
                text_col(COL_CHANGED, value);
            else
                igTextUnformatted(value, NULL);

            if (row->offset == offsetof(em_x86_regs, core.rflags)) {
                flags_text(v, value, sizeof value);
                igTableNextRow(0, 0);
                igTableSetColumnIndex(1);
                text_col(COL_DIM, value);
            }
        }
        igEndTable();
    }

    /* Ctrl+C copies the selected register's value. */
    if (app->sel_reg >= 0 && (size_t)app->sel_reg < sizeof rows / sizeof rows[0] &&
        rows[app->sel_reg].name && igIsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        igIsKeyChordPressed_Nil(ImGuiMod_Ctrl | ImGuiKey_C)) {
        format_value(regs, &rows[app->sel_reg], value, sizeof value);
        igSetClipboardText(value);
    }
    igEnd();
}
