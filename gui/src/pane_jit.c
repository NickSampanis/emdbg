/* Guest instructions next to the host code the target's JIT generated for them, grouped
 * by translation block. The protocol has no JIT queries yet, so the pane shows a fixed
 * sample (what QEMU TCG might produce for the fake target's checksum loop) to keep the
 * layout in shape. */
#include "app.h"

#include <inttypes.h>
#include <stdio.h>

/* One row: a guest instruction and one of the host instructions generated for it.
 * Rows continuing the previous guest instruction have guest_text == NULL. */
typedef struct jit_row {
    uint64_t    guest_addr;
    const char *guest_text;
    uint64_t    host_addr;
    const char *host_text;
} jit_row;

typedef struct jit_block {
    uint64_t       guest_start;
    uint32_t       guest_size;
    uint64_t       host_start;
    uint32_t       host_size;
    const jit_row *rows;
    int            row_count;
} jit_block;

static const jit_row tb0_rows[] = {
    { 0x401000, "xor eax, eax",   0x7f3a0f00, "xor ebp, ebp" },
    { 0x401000, NULL,             0x7f3a0f02, "mov [r14+0x00], rbp" },
    { 0x401002, "test esi, esi",  0x7f3a0f06, "mov r12d, [r14+0x30]" },
    { 0x401002, NULL,             0x7f3a0f0a, "test r12d, r12d" },
    { 0x401004, "je 0x401017",    0x7f3a0f0d, "je 0x7f3a0f1a" },
    { 0x401004, NULL,             0x7f3a0f13, "jmp 0x7f3a0f30          ; goto_tb 0x401006" },
    { 0x401004, NULL,             0x7f3a0f1a, "mov qword [r14+0x80], 0x401017" },
    { 0x401004, NULL,             0x7f3a0f25, "jmp 0x7f3a0018          ; exit_tb" },
};

static const jit_row tb1_rows[] = {
    { 0x401008, "movzx edx, byte ptr [rdi+rcx]", 0x7f3a1000, "mov rbx, [r14+0x38]" },
    { 0x401008, NULL,                            0x7f3a1004, "add rbx, [r14+0x08]" },
    { 0x401008, NULL,                            0x7f3a1008, "movzx ebx, byte [rbx]   ; softmmu fast path" },
    { 0x401008, NULL,                            0x7f3a100b, "mov [r14+0x10], rbx" },
    { 0x40100C, "add eax, eax",                  0x7f3a100f, "mov ebp, [r14+0x00]" },
    { 0x40100C, NULL,                            0x7f3a1013, "add ebp, ebp" },
    { 0x40100E, "xor eax, edx",                  0x7f3a1015, "xor ebp, ebx" },
    { 0x40100E, NULL,                            0x7f3a1017, "mov [r14+0x00], rbp" },
    { 0x401010, "inc rcx",                       0x7f3a101b, "mov r12, [r14+0x08]" },
    { 0x401010, NULL,                            0x7f3a101f, "inc r12" },
    { 0x401010, NULL,                            0x7f3a1022, "mov [r14+0x08], r12" },
    { 0x401013, "cmp esi, ecx",                  0x7f3a1026, "mov r13d, [r14+0x30]" },
    { 0x401013, NULL,                            0x7f3a102a, "cmp r13d, r12d" },
    { 0x401015, "jne 0x401008",                  0x7f3a102d, "jne 0x7f3a1000          ; chained to self" },
    { 0x401015, NULL,                            0x7f3a1033, "mov qword [r14+0x80], 0x401017" },
    { 0x401015, NULL,                            0x7f3a103e, "jmp 0x7f3a0018          ; exit_tb" },
};

static const jit_block sample_blocks[] = {
    { 0x401000, 6,  0x7f3a0f00, 0x2a, tb0_rows, (int)(sizeof tb0_rows / sizeof tb0_rows[0]) },
    { 0x401008, 15, 0x7f3a1000, 0x43, tb1_rows, (int)(sizeof tb1_rows / sizeof tb1_rows[0]) },
};

static void block_header(const jit_block *b)
{
    char text[128];

    snprintf(text, sizeof text,
             "TB 0x%" PRIX64 "  (guest %" PRIu32 " bytes -> host 0x%" PRIX64 ", %" PRIu32 " bytes)",
             b->guest_start, b->guest_size, b->host_start, b->host_size);
    igSeparatorText(text);
}

static void block_table(app_state *app, const jit_block *b, int block_index, uint64_t pc)
{
    ImGuiTableFlags flags = ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit;
    const jit_row  *r;
    bool            first;
    char            addr[24];
    int             i;

    igPushID_Int(block_index);
    if (igBeginTable("tb", 4, flags, v2(0, 0), 0)) {
        igTableSetupColumn("guest addr", ImGuiTableColumnFlags_WidthFixed, 0, 0);
        igTableSetupColumn("guest insn", ImGuiTableColumnFlags_WidthFixed, 0, 0);
        igTableSetupColumn("host addr", ImGuiTableColumnFlags_WidthFixed, 0, 0);
        igTableSetupColumn("host insns", ImGuiTableColumnFlags_WidthStretch, 0, 0);
        if (block_index == 0)
            igTableHeadersRow();

        for (i = 0; i < b->row_count; i++) {
            r     = &b->rows[i];
            first = r->guest_text != NULL;

            igTableNextRow(0, 0);
            if (r->guest_addr == pc)
                igTableSetBgColor(ImGuiTableBgTarget_RowBg1, COL_PC_BG, -1);

            igTableSetColumnIndex(0);
            igPushID_Int(i);
            snprintf(addr, sizeof addr, "0x%" PRIX64 "##g", r->guest_addr);
            /* Continuation rows keep a (transparent) label so the whole row
             * stays clickable. */
            igPushStyleColor_U32(ImGuiCol_Text, first ? COL_ADDR : 0);
            if (igSelectable_Bool(addr, r->guest_addr == app->selected,
                                  ImGuiSelectableFlags_SpanAllColumns, v2(0, 0)))
                app_select(app, r->guest_addr, PANE_JIT);
            igPopStyleColor(1);
            igPopID();

            if ((app->scroll_mask & PANE_JIT) && first && r->guest_addr == app->selected)
                igSetScrollHereY(0.3f);

            igTableSetColumnIndex(1);
            if (first)
                igTextUnformatted(r->guest_text, NULL);

            snprintf(addr, sizeof addr, "0x%" PRIX64, r->host_addr);
            igTableSetColumnIndex(2);
            text_col(COL_DIM, addr);
            igTableSetColumnIndex(3);
            igTextUnformatted(r->host_text, NULL);
        }
        igEndTable();
    }
    igPopID();
}

void pane_jit(app_state *app)
{
    const em_hello_rep *target;
    const em_x86_regs  *regs;
    uint64_t            pc;
    int                 i;

    if (!app->show_jit)
        return;
    if (!igBegin(WIN_JIT, &app->show_jit, 0)) {
        igEnd();
        app->scroll_mask &= ~PANE_JIT;
        return;
    }

    target = app->dbg ? dbg_target(app->dbg) : NULL;
    regs = app->dbg ? dbg_regs(app->dbg) : NULL;
    pc = regs ? regs->core.rip : 0;
    if (target && (target->features & EM_FEAT_JIT))
        igTextDisabled("The target has a JIT, but dbgeng cannot query it yet. Sample data:");
    else
        igTextDisabled("Sample data: the target reports no JIT, and JIT queries are not in "
                       "the protocol yet.");

    igBeginChild_Str("blocks", v2(0, 0), 0, 0);
    for (i = 0; i < (int)(sizeof sample_blocks / sizeof sample_blocks[0]); i++) {
        block_header(&sample_blocks[i]);
        block_table(app, &sample_blocks[i], i, pc);
    }
    igEndChild();
    app->scroll_mask &= ~PANE_JIT;
    igEnd();
}
