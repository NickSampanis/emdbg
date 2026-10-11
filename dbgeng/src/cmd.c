#include "cmd.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE        1024
#define MAX_DUMP_BYTES  0x100000u
#define MAX_EDIT_VALUES 256
#define MAX_SYMBOL_LINES 500
#define MAX_FIND_MATCHES 64

enum { PATH_SYMBOL, PATH_SOURCE, PATH_EXECUTABLE };

enum {
    STEP_INTO,
    STEP_OVER,
    STEP_OUT,
    STEP_LINE_INTO,
    STEP_LINE_OVER,
    STEP_TO_CALL,
    STEP_TO_BRANCH,
};

enum { STACK_PLAIN, STACK_CALLS, STACK_VERBOSE };

#define MAX_STACK_FRAMES 0x100

static const char *const path_kinds[] = { "symbol", "source", "executable" };

enum {
    CMD_TARGET  = 1 << 0,
    CMD_STOPPED = 1 << 1,
    CMD_REPEAT  = 1 << 2,
};

typedef dbg_status (*cmd_fn)(dbg_ctx *dbg, cmd_args *args, uintptr_t arg);

typedef struct cmd_def {
    const char *name;
    cmd_fn      fn;
    uintptr_t   arg;
    unsigned    flags;
    const char *usage;
    const char *help;
} cmd_def;

enum { FMT_HEX, FMT_ASCII, FMT_UNICODE };
#define MEM_ARG(width, fmt, phys)  ((uintptr_t)(width) | ((uintptr_t)(fmt) << 8) | ((uintptr_t)(phys) << 16))
#define ARG_WIDTH(arg)             ((unsigned)((arg) & 0xFF))
#define ARG_FMT(arg)               ((unsigned)(((arg) >> 8) & 0xFF))
#define ARG_SPACE(arg)             ((uint8_t)(((arg) >> 16) & 1) ? EM_SPACE_PHYS : EM_SPACE_VIRT)

static dbg_status arg_end(cmd_args *args)
{
    if (!cmd_at_end(args))
        return cmd_fail(args, NULL, "unexpected '%s'", args->cursor);
    return DBG_OK;
}

static dbg_status arg_range(dbg_ctx *dbg, cmd_args *args, unsigned width, uint64_t *addr,
                            uint64_t *count)
{
    const char *end_at;
    uint64_t    end;
    dbg_status  status;

    status = expr_eval(dbg, args, addr);
    if (status != DBG_OK)
        return status;
    if (cmd_at_end(args))
        return DBG_OK;
    if (*args->cursor == 'l' || *args->cursor == 'L') {
        args->cursor++;
        return expr_eval(dbg, args, count);
    }
    end_at = args->cursor;
    status = expr_eval(dbg, args, &end);
    if (status != DBG_OK)
        return status;
    if (end < *addr)
        return cmd_fail(args, end_at, "end address is below the start address");
    *count = (end - *addr) / width + 1;
    return DBG_OK;
}

static size_t arg_word(cmd_args *args, char *buf, size_t cap)
{
    size_t len;

    len = 0;
    cmd_skip_ws(args);
    while (*args->cursor && *args->cursor != ' ' && *args->cursor != '\t') {
        if (len + 1 < cap)
            buf[len++] = *args->cursor;
        args->cursor++;
    }
    buf[len] = '\0';
    return len;
}

static dbg_status arg_path(cmd_args *args, char *buf, size_t cap)
{
    const char *start;
    size_t      len;
    bool        quoted;

    len = 0;
    cmd_skip_ws(args);
    start = args->cursor;
    quoted = *args->cursor == '"';
    if (quoted)
        args->cursor++;
    while (*args->cursor && (quoted ? *args->cursor != '"'
                                    : *args->cursor != ' ' && *args->cursor != '\t')) {
        if (len + 1 >= cap)
            return cmd_fail(args, start, "path too long");
        buf[len++] = *args->cursor++;
    }
    if (quoted) {
        if (*args->cursor != '"')
            return cmd_fail(args, start, "missing closing quote");
        args->cursor++;
    }
    buf[len] = '\0';
    return DBG_OK;
}

static void hex64(char *buf, size_t cap, uint64_t value)
{
    snprintf(buf, cap, "%08" PRIx32 "`%08" PRIx32, (uint32_t)(value >> 32), (uint32_t)value);
}

static dbg_status cmd_go(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    dbg_status status;

    (void)arg;
    status = arg_end(args);
    return status != DBG_OK ? status : dbg_continue(dbg);
}

static void print_insn(dbg_ctx *dbg, const dbg_insn *insn)
{
    dbg_symbol symbol;
    char       addr_text[24];
    char       bytes[32];
    char       target_name[160];
    uint32_t   index;
    size_t     pos;

    pos = 0;
    bytes[0] = '\0';
    if (dbg_sym_name(dbg, insn->addr, &symbol) && symbol.function && symbol.offset == 0)
        dbg_out(dbg, DBG_OUT_NORMAL, "%s!%s:\n", symbol.module, symbol.function);
    hex64(addr_text, sizeof addr_text, insn->addr);
    for (index = 0; index < insn->len && pos + 3 < sizeof bytes; index++)
        pos += (size_t)snprintf(bytes + pos, sizeof bytes - pos, "%02x", insn->bytes[index]);
    if (insn->has_target && dbg_sym_format(dbg, insn->target, target_name, sizeof target_name))
        dbg_out(dbg, DBG_OUT_NORMAL, "%s %-16s %s (%s)\n", addr_text, bytes, insn->text,
                target_name);
    else
        dbg_out(dbg, DBG_OUT_NORMAL, "%s %-16s %s\n", addr_text, bytes, insn->text);
}

static void print_location(dbg_ctx *dbg)
{
    dbg_insn   insn;
    dbg_source source;
    uint32_t   count;
    char       addr_text[24];

    count = 0;
    if (dbg_get_state(dbg) != DBG_STATE_STOPPED)
        return;
    if (dbg_source_at(dbg, dbg_pc(dbg), &source))
        dbg_out(dbg, DBG_OUT_NORMAL, "%s(%u)\n", source.file, source.line);
    if (dbg_disasm(dbg, dbg_pc(dbg), &insn, 1, &count) == DBG_OK && count == 1) {
        print_insn(dbg, &insn);
    } else {
        hex64(addr_text, sizeof addr_text, dbg_pc(dbg));
        dbg_out(dbg, DBG_OUT_NORMAL, "%s ??\n", addr_text);
    }
}

static dbg_status step_by_kind(dbg_ctx *dbg, uintptr_t kind)
{
    switch (kind) {
        case STEP_OUT:
            return dbg_step_out(dbg);
        case STEP_OVER:
            return dbg_get_source_step(dbg) ? dbg_step_line(dbg, false) : dbg_step_over(dbg);
        case STEP_LINE_INTO:
            return dbg_step_line(dbg, true);
        case STEP_LINE_OVER:
            return dbg_step_line(dbg, false);
        case STEP_TO_CALL:
            return dbg_step_to_call(dbg);
        case STEP_TO_BRANCH:
            return dbg_step_to_branch(dbg);
        default:
            return dbg_get_source_step(dbg) ? dbg_step_line(dbg, true) : dbg_step(dbg);
    }
}

static dbg_status cmd_step(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    dbg_status status;

    status = arg_end(args);
    if (status != DBG_OK)
        return status;
    status = step_by_kind(dbg, arg);
    if (status == DBG_OK)
        print_location(dbg);
    return status;
}

static dbg_status cmd_source_mode(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    dbg_status status;

    status = arg_end(args);
    if (status != DBG_OK)
        return status;
    dbg_set_source_step(dbg, arg != 0);
    dbg_out(dbg, DBG_OUT_NORMAL, "t and p now step by %s\n",
            arg ? "source line" : "instruction");
    return DBG_OK;
}

static dbg_status cmd_unasm(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    dbg_insn   insns[32];
    uint64_t   addr;
    uint64_t   count;
    uint32_t   decoded;
    uint32_t   index;
    uint32_t   want;
    dbg_status status;

    (void)arg;
    count = 8;
    if (cmd_at_end(args)) {
        if (dbg->have_next_unasm)
            addr = dbg->next_unasm;
        else if (dbg_get_state(dbg) == DBG_STATE_STOPPED)
            addr = dbg_pc(dbg);
        else
            return cmd_fail(args, NULL, "expected an address");
    } else {
        status = expr_eval(dbg, args, &addr);
        if (status != DBG_OK)
            return status;
        if (!cmd_at_end(args)) {
            if (*args->cursor != 'l' && *args->cursor != 'L')
                return cmd_fail(args, NULL, "expected L<count>");
            args->cursor++;
            status = expr_eval(dbg, args, &count);
            if (status != DBG_OK)
                return status;
        }
        status = arg_end(args);
        if (status != DBG_OK)
            return status;
    }
    if (count == 0 || count > 4096)
        return cmd_fail(args, NULL, "count must be 1 to 0x1000 instructions");

    while (count) {
        want = count < 32 ? (uint32_t)count : 32;
        status = dbg_disasm(dbg, addr, insns, want, &decoded);
        if (status != DBG_OK)
            return status;
        for (index = 0; index < decoded; index++)
            print_insn(dbg, &insns[index]);
        if (decoded == 0)
            break;
        addr = insns[decoded - 1].addr + insns[decoded - 1].len;
        count -= decoded;
        if (decoded < want)
            break;
    }
    dbg->next_unasm = addr;
    dbg->have_next_unasm = true;
    return DBG_OK;
}

static const char *bp_type_name(uint8_t type)
{
    switch (type) {
        case EM_BP_EXEC:
            return "exec";
        case EM_BP_WRITE:
            return "write";
        case EM_BP_READ:
            return "read";
    }
    return "access";
}

static void print_bp_added(dbg_ctx *dbg, uint32_t id)
{
    const dbg_bp *bp;
    char          addr_text[24];
    int           index;

    bp = NULL;
    for (index = 0; index < dbg_bp_count(dbg) && !bp; index++)
        if (dbg_bp_get(dbg, index)->id == id)
            bp = dbg_bp_get(dbg, index);
    if (!bp)
        return;
    hex64(addr_text, sizeof addr_text, bp->addr);
    if (bp->type == EM_BP_EXEC)
        dbg_out(dbg, DBG_OUT_NORMAL, "Breakpoint %u at %s [%s]\n", id, addr_text,
                dbg_bp_where(dbg, id));
    else
        dbg_out(dbg, DBG_OUT_NORMAL, "Breakpoint %u at %s, %s %u byte(s) [%s]\n", id, addr_text,
                bp_type_name(bp->type), bp->len, dbg_bp_where(dbg, id));
}

static dbg_status cmd_bp(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    uint64_t   addr;
    uint32_t   id;
    dbg_status status;

    (void)arg;
    if (cmd_at_end(args))
        return cmd_fail(args, NULL, "expected an address");
    status = expr_eval(dbg, args, &addr);
    if (status == DBG_OK)
        status = arg_end(args);
    if (status != DBG_OK)
        return status;
    status = dbg_bp_add(dbg, EM_BP_EXEC, addr, 1, &id);
    if (status == DBG_OK)
        print_bp_added(dbg, id);
    return status;
}

static dbg_status cmd_ba(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    const char *size_at;
    uint64_t    size;
    uint64_t    addr;
    uint32_t    id;
    uint8_t     type;
    dbg_status  status;

    (void)arg;
    cmd_skip_ws(args);
    switch (tolower((unsigned char)*args->cursor)) {
        case 'e':
            type = EM_BP_EXEC;
            break;
        case 'w':
            type = EM_BP_WRITE;
            break;
        case 'r':
            type = EM_BP_READ;
            break;
        case 'a':
            type = EM_BP_ACCESS;
            break;
        default:
            return cmd_fail(args, NULL, "expected e, r, w or a");
    }
    args->cursor++;
    if (*args->cursor != ' ' && *args->cursor != '\t')
        return cmd_fail(args, NULL, "expected a space after the access type");
    cmd_skip_ws(args);
    size_at = args->cursor;
    status = expr_eval(dbg, args, &size);
    if (status != DBG_OK)
        return status;
    if (size != 1 && size != 2 && size != 4 && size != 8)
        return cmd_fail(args, size_at, "size must be 1, 2, 4 or 8");
    if (type == EM_BP_EXEC && size != 1)
        return cmd_fail(args, size_at, "execute breakpoints have size 1");
    if (cmd_at_end(args))
        return cmd_fail(args, NULL, "expected an address");
    status = expr_eval(dbg, args, &addr);
    if (status == DBG_OK)
        status = arg_end(args);
    if (status != DBG_OK)
        return status;
    if (addr & (size - 1))
        return cmd_fail(args, NULL, "address must be aligned to the size");
    status = dbg_bp_add(dbg, type, addr, (uint8_t)size, &id);
    if (status == DBG_OK)
        print_bp_added(dbg, id);
    return status;
}

static dbg_status cmd_bl(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    const dbg_bp *bp;
    char          addr_text[24];
    dbg_status    status;
    int           index;

    (void)arg;
    status = arg_end(args);
    if (status != DBG_OK)
        return status;
    if (!dbg_bp_count(dbg))
        dbg_out(dbg, DBG_OUT_NORMAL, "no breakpoints\n");
    for (index = 0; index < dbg_bp_count(dbg); index++) {
        bp = dbg_bp_get(dbg, index);
        hex64(addr_text, sizeof addr_text, bp->addr);
        dbg_out(dbg, DBG_OUT_NORMAL, " %3u %c %s  %-6s %u  hits %-5u [%s]\n", bp->id,
                bp->enabled ? 'e' : 'd', addr_text, bp_type_name(bp->type), bp->len, bp->hits,
                dbg_bp_where(dbg, bp->id));
    }
    return DBG_OK;
}

static int bp_exists(const dbg_ctx *dbg, uint32_t id)
{
    int index;

    for (index = 0; index < dbg_bp_count(dbg); index++)
        if (dbg_bp_get(dbg, index)->id == id)
            return 1;
    return 0;
}

static dbg_status cmd_bc(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    const char   *start;
    char         *end;
    unsigned long number;
    dbg_status    status;
    dbg_status    last;
    int           index;

    last = DBG_OK;
    if (cmd_at_end(args))
        return cmd_fail(args, NULL, "expected breakpoint numbers or *");
    if (*args->cursor == '*') {
        args->cursor++;
        status = arg_end(args);
        if (status != DBG_OK)
            return status;
        if (arg == 0) {
            while (dbg_bp_count(dbg) && last == DBG_OK)
                last = dbg_bp_remove(dbg, dbg_bp_get(dbg, 0)->id);
        } else {
            for (index = 0; index < dbg_bp_count(dbg); index++) {
                status = dbg_bp_enable(dbg, dbg_bp_get(dbg, index)->id, arg == 2);
                if (status != DBG_OK)
                    last = status;
            }
        }
        return last;
    }

    for (start = args->cursor; !cmd_at_end(args); ) {
        if (!isdigit((unsigned char)*args->cursor))
            return cmd_fail(args, NULL, "expected a breakpoint number");
        number = strtoul(args->cursor, &end, 10);
        if (!bp_exists(dbg, (uint32_t)number))
            return cmd_fail(args, NULL, "no breakpoint %lu (see bl)", number);
        args->cursor = end;
        if (*args->cursor == ',')
            args->cursor++;
    }
    for (args->cursor = start; !cmd_at_end(args); ) {
        number = strtoul(args->cursor, &end, 10);
        args->cursor = end;
        if (*args->cursor == ',')
            args->cursor++;
        if (arg == 0)
            status = dbg_bp_remove(dbg, (uint32_t)number);
        else
            status = dbg_bp_enable(dbg, (uint32_t)number, arg == 2);
        if (status != DBG_OK) {
            dbg_out(dbg, DBG_OUT_ERROR, "breakpoint %lu: %s\n", number, dbg_status_str(status));
            last = status;
        }
    }
    return last;
}

static dbg_status cmd_pause(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    dbg_status status;

    (void)arg;
    status = arg_end(args);
    if (status != DBG_OK)
        return status;
    if (dbg_get_state(dbg) == DBG_STATE_STOPPED) {
        dbg_out(dbg, DBG_OUT_NORMAL, "target is already stopped\n");
        return DBG_OK;
    }
    status = dbg_pause(dbg);
    if (status == DBG_OK && dbg_get_state(dbg) == DBG_STATE_STOPPED)
        print_location(dbg);
    return status;
}

static void print_regs(dbg_ctx *dbg)
{
    const em_x86_regs *regs;
    const em_x86_core *core;
    uint64_t           flags;

    regs = &dbg->regs;
    core = &regs->core;
    flags = core->rflags;
    dbg_out(dbg, DBG_OUT_NORMAL, "rax=%016" PRIx64 " rbx=%016" PRIx64 " rcx=%016" PRIx64 "\n",
            core->rax, core->rbx, core->rcx);
    dbg_out(dbg, DBG_OUT_NORMAL, "rdx=%016" PRIx64 " rsi=%016" PRIx64 " rdi=%016" PRIx64 "\n",
            core->rdx, core->rsi, core->rdi);
    dbg_out(dbg, DBG_OUT_NORMAL, "rip=%016" PRIx64 " rsp=%016" PRIx64 " rbp=%016" PRIx64 "\n",
            core->rip, core->rsp, core->rbp);
    dbg_out(dbg, DBG_OUT_NORMAL, " r8=%016" PRIx64 "  r9=%016" PRIx64 " r10=%016" PRIx64 "\n",
            core->r8, core->r9, core->r10);
    dbg_out(dbg, DBG_OUT_NORMAL, "r11=%016" PRIx64 " r12=%016" PRIx64 " r13=%016" PRIx64 "\n",
            core->r11, core->r12, core->r13);
    dbg_out(dbg, DBG_OUT_NORMAL, "r14=%016" PRIx64 " r15=%016" PRIx64 "\n", core->r14, core->r15);
    dbg_out(dbg, DBG_OUT_NORMAL, "iopl=%u %s %s %s %s %s %s %s %s\n",
            (unsigned)((flags >> 12) & 3),
            flags & (1u << 11) ? "ov" : "nv", flags & (1u << 10) ? "dn" : "up",
            flags & (1u << 9) ? "ei" : "di",  flags & (1u << 7) ? "ng" : "pl",
            flags & (1u << 6) ? "zr" : "nz",  flags & (1u << 4) ? "ac" : "na",
            flags & (1u << 2) ? "pe" : "po",  flags & (1u << 0) ? "cy" : "nc");
    if (regs->valid & EM_RB_BIT(EM_RB_X86_SEG))
        dbg_out(dbg, DBG_OUT_NORMAL,
                "cs=%04x  ss=%04x  ds=%04x  es=%04x  fs=%04x  gs=%04x             efl=%08" PRIx32 "\n",
                regs->seg.cs.selector, regs->seg.ss.selector, regs->seg.ds.selector,
                regs->seg.es.selector, regs->seg.fs.selector, regs->seg.gs.selector,
                (uint32_t)flags);
}

static dbg_status cmd_reg(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    const reg_def *reg;
    const char    *name;
    size_t         len;
    uint64_t       value;
    dbg_status     status;

    (void)arg;
    if (cmd_at_end(args)) {
        print_regs(dbg);
        return DBG_OK;
    }
    if (*args->cursor == '@')
        args->cursor++;
    name = args->cursor;
    while (isalnum((unsigned char)*args->cursor))
        args->cursor++;
    len = (size_t)(args->cursor - name);
    reg = reg_find(name, len);
    if (!reg)
        return cmd_fail(args, name, "unknown register '%.*s'", (int)len, name);
    if (!(dbg->regs.valid & EM_RB_BIT(reg->block)))
        return cmd_fail(args, name, "register '%s' is not available on this target", reg->name);

    if (cmd_at_end(args)) {
        dbg_out(dbg, DBG_OUT_NORMAL, "%s=%0*" PRIx64 "\n", reg->name, reg->size * 2,
                reg_get(&dbg->regs, reg));
        return DBG_OK;
    }
    if (*args->cursor != '=')
        return cmd_fail(args, NULL, "expected '='");
    args->cursor++;
    status = expr_eval(dbg, args, &value);
    if (status != DBG_OK)
        return status;
    status = arg_end(args);
    if (status != DBG_OK)
        return status;
    reg_set(&dbg->regs, reg, value);
    return dbg_put_regs(dbg, reg->block);
}

static void dump_hex(dbg_ctx *dbg, uint64_t addr, const uint8_t *buf, uint32_t len,
                     uint32_t valid, unsigned width)
{
    char     line[160];
    char     addr_text[24];
    uint32_t offset;
    uint32_t index;
    uint32_t byte_index;
    uint64_t value;
    size_t   pos;
    char     separator;

    for (offset = 0; offset < len; offset += 16) {
        hex64(addr_text, sizeof addr_text, addr + offset);
        pos = (size_t)snprintf(line, sizeof line, "%s ", addr_text);
        for (index = offset; index < offset + 16 && index < len; index += width) {
            separator = (width == 1 && index == offset + 8) ? '-' : ' ';
            if (index + width <= valid) {
                value = 0;
                for (byte_index = 0; byte_index < width; byte_index++)
                    value |= (uint64_t)buf[index + byte_index] << (byte_index * 8);
                pos += (size_t)snprintf(line + pos, sizeof line - pos, "%c%0*" PRIx64, separator,
                                        (int)width * 2, value);
            } else {
                pos += (size_t)snprintf(line + pos, sizeof line - pos, "%c%.*s", separator,
                                        (int)width * 2, "????????????????");
            }
        }
        if (width == 1) {
            while (pos < 19 + 16 * 3 + 1)
                line[pos++] = ' ';
            for (index = offset; index < offset + 16 && index < len; index++)
                line[pos++] = index < valid && isprint(buf[index]) ? (char)buf[index] : '.';
            line[pos] = '\0';
        }
        dbg_out(dbg, DBG_OUT_NORMAL, "%s\n", line);
    }
}

static void dump_string(dbg_ctx *dbg, uint64_t addr, const uint8_t *buf, uint32_t valid,
                        unsigned width)
{
    char     text[512];
    char     addr_text[24];
    uint32_t index;
    size_t   len;
    unsigned ch;

    len = 0;
    for (index = 0; index + width <= valid && len < sizeof text - 1; index += width) {
        ch = width == 2 ? (unsigned)(buf[index] | (buf[index + 1] << 8)) : buf[index];
        if (!ch)
            break;
        text[len++] = ch < 0x80 && isprint((int)ch) ? (char)ch : '.';
    }
    text[len] = '\0';
    hex64(addr_text, sizeof addr_text, addr);
    dbg_out(dbg, DBG_OUT_NORMAL, "%s  \"%s\"\n", addr_text, text);
}

static dbg_status cmd_dump(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    const em_x86_regs *regs;
    unsigned           width;
    unsigned           fmt;
    uint64_t           addr;
    uint64_t           count;
    uint64_t           bytes;
    uint32_t           done;
    uint8_t           *buf;
    dbg_status         status;

    width = ARG_WIDTH(arg);
    fmt = ARG_FMT(arg);
    done = 0;
    count = fmt == FMT_HEX ? 0x80 / width : 0x100 / width;
    if (!cmd_at_end(args)) {
        status = arg_range(dbg, args, width, &addr, &count);
        if (status != DBG_OK)
            return status;
        status = arg_end(args);
        if (status != DBG_OK)
            return status;
    } else if (dbg->have_next_dump) {
        addr = dbg->next_dump;
    } else if ((regs = dbg_regs(dbg)) != NULL) {
        addr = regs->core.rip;
    } else {
        return cmd_fail(args, NULL, "expected an address");
    }

    bytes = count * width;
    if (count == 0 || bytes / width != count || bytes > MAX_DUMP_BYTES)
        return cmd_fail(args, NULL, "range must be 1 to 0x%x bytes", MAX_DUMP_BYTES);
    buf = malloc((size_t)bytes);
    if (!buf)
        return DBG_E_NOMEM;

    status = dbg_read_mem(dbg, ARG_SPACE(arg), addr, buf, (uint32_t)bytes, &done);
    if (done || status == DBG_OK) {
        if (fmt == FMT_HEX)
            dump_hex(dbg, addr, buf, (uint32_t)bytes, done, width);
        else
            dump_string(dbg, addr, buf, done, width);
        status = DBG_OK;
    }
    free(buf);
    dbg->next_dump = addr + bytes;
    dbg->have_next_dump = true;
    return status;
}

static dbg_status cmd_edit(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    unsigned   width;
    uint8_t    buf[MAX_EDIT_VALUES * 8];
    uint64_t   addr;
    uint64_t   value;
    uint32_t   values;
    uint32_t   done;
    dbg_status status;

    width = ARG_WIDTH(arg);
    values = 0;
    status = expr_eval(dbg, args, &addr);
    if (status != DBG_OK)
        return status;
    if (cmd_at_end(args))
        return cmd_fail(args, NULL, "expected a value to write");
    while (!cmd_at_end(args)) {
        if (values == MAX_EDIT_VALUES)
            return cmd_fail(args, NULL, "at most %d values per command", MAX_EDIT_VALUES);
        status = expr_eval(dbg, args, &value);
        if (status != DBG_OK)
            return status;
        memcpy(buf + values * width, &value, width);
        values++;
    }
    status = dbg_write_mem(dbg, ARG_SPACE(arg), addr, buf, values * width, &done);
    if (status != DBG_OK)
        dbg_out(dbg, DBG_OUT_ERROR, "wrote %u of %u bytes\n", done, values * width);
    return status;
}

static dbg_status cmd_eval(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    char       hex_text[24];
    uint64_t   value;
    dbg_status status;

    (void)arg;
    status = expr_eval(dbg, args, &value);
    if (status == DBG_OK)
        status = arg_end(args);
    if (status != DBG_OK)
        return status;
    hex64(hex_text, sizeof hex_text, value);
    dbg_out(dbg, DBG_OUT_NORMAL, "Evaluate expression: %" PRIu64 " = %s\n", value, hex_text);
    return DBG_OK;
}

static dbg_status cmd_vtop(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    char       va_text[24];
    char       pa_text[24];
    uint64_t   va;
    uint64_t   pa;
    uint32_t   flags;
    dbg_status status;

    (void)arg;
    status = expr_eval(dbg, args, &va);
    if (status == DBG_OK)
        status = arg_end(args);
    if (status != DBG_OK)
        return status;
    status = dbg_translate(dbg, va, &pa, &flags);
    if (status == DBG_E_FAULT) {
        hex64(va_text, sizeof va_text, va);
        dbg_out(dbg, DBG_OUT_NORMAL, "%s is not mapped\n", va_text);
        return DBG_OK;
    }
    if (status != DBG_OK)
        return status;
    hex64(va_text, sizeof va_text, va);
    hex64(pa_text, sizeof pa_text, pa);
    dbg_out(dbg, DBG_OUT_NORMAL, "%s -> phys %s  %s %s%s%s\n", va_text, pa_text,
            flags & EM_XLATE_WRITABLE ? "rw" : "ro", flags & EM_XLATE_USER ? "user" : "kernel",
            flags & EM_XLATE_NX ? " nx" : "",
            flags & EM_XLATE_HUGE ? " 1G" : flags & EM_XLATE_LARGE ? " large" : "");
    return DBG_OK;
}

static dbg_status cmd_connect(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    char     host[256];
    char     port_text[16];
    char    *colon;
    unsigned port;

    (void)arg;
    port = 4242;
    if (!arg_word(args, host, sizeof host))
        strcpy(host, "127.0.0.1");
    colon = strrchr(host, ':');
    if (colon && colon == strchr(host, ':')) {
        *colon = '\0';
        port = (unsigned)strtoul(colon + 1, NULL, 10);
    }
    if (arg_word(args, port_text, sizeof port_text))
        port = (unsigned)strtoul(port_text, NULL, 10);
    if (!cmd_at_end(args))
        return cmd_fail(args, NULL, "unexpected '%s'", args->cursor);
    if (port == 0 || port > 65535)
        return cmd_fail(args, NULL, "bad port");
    return dbg_connect(dbg, host, (uint16_t)port);
}

static dbg_status cmd_disconnect(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    dbg_status status;

    (void)arg;
    status = arg_end(args);
    if (status != DBG_OK)
        return status;
    dbg_disconnect(dbg);
    dbg_out(dbg, DBG_OUT_NORMAL, "disconnected\n");
    return DBG_OK;
}

static dbg_status cmd_monitor(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    (void)arg;
    if (cmd_at_end(args))
        return cmd_fail(args, NULL, "expected a command for the target");
    return dbg_monitor(dbg, args->cursor);
}

static dbg_status cmd_lds(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    char        path[512];
    const char *path_at;
    const char *end_at;
    uint64_t    base;
    uint64_t    end;
    dbg_status  status;

    (void)arg;
    cmd_skip_ws(args);
    path_at = args->cursor;
    /* parse the symbol filename */
    status = arg_path(args, path, sizeof path);
    if (status != DBG_OK)
        return status;
    if (!path[0])
        return cmd_fail(args, path_at, "expected a symbol file");
    if (cmd_at_end(args))
        return cmd_fail(args, NULL, "expected a base address or a range to scan");
    /* parse the base address(can be an expression) */
    status = expr_eval(dbg, args, &base);
    if (status != DBG_OK)
        return status;
    /* if there is no end address, load the symbol at base address without a lookup */
    if (cmd_at_end(args))
        return dbg_sym_load(dbg, path, base);
    end_at = args->cursor;
    /* parse the base end address(can be an expression) */
    status = expr_eval(dbg, args, &end);
    if (status == DBG_OK)
        status = arg_end(args);
    if (status != DBG_OK)
        return status;
    if (end < base)
        return cmd_fail(args, end_at, "end address is below the start address");
    if (dbg_get_state(dbg) != DBG_STATE_STOPPED)
        return cmd_fail(args, path_at, "scanning needs a stopped target");
    return dbg_sym_scan(dbg, path, base, end);
}

static dbg_status cmd_lm(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    const dbg_module *module;
    char              base_text[24];
    char              end_text[24];
    dbg_status        status;
    int               index;

    (void)arg;
    status = arg_end(args);
    if (status != DBG_OK)
        return status;
    if (!dbg_module_count(dbg))
        dbg_out(dbg, DBG_OUT_NORMAL, "no symbols loaded (use lds)\n");
    for (index = 0; index < dbg_module_count(dbg); index++) {
        module = dbg_module_get(dbg, index);
        hex64(base_text, sizeof base_text, module->base);
        hex64(end_text, sizeof end_text, module->end);
        dbg_out(dbg, DBG_OUT_NORMAL, "%s %s  %-20s %6u functions %7u lines  %s\n", base_text,
                end_text, module->name, module->function_count, module->line_count,
                module->symbol_file);
    }
    return DBG_OK;
}

static dbg_status cmd_ln(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    dbg_source source;
    char       name[160];
    char       addr_text[24];
    uint64_t   addr;
    dbg_status status;

    (void)arg;
    if (cmd_at_end(args)) {
        if (dbg_get_state(dbg) != DBG_STATE_STOPPED)
            return cmd_fail(args, NULL, "expected an address");
        addr = dbg_pc(dbg);
    } else {
        status = expr_eval(dbg, args, &addr);
        if (status == DBG_OK)
            status = arg_end(args);
        if (status != DBG_OK)
            return status;
    }
    hex64(addr_text, sizeof addr_text, addr);
    if (!dbg_sym_format(dbg, addr, name, sizeof name)) {
        dbg_out(dbg, DBG_OUT_NORMAL, "%s: no symbol\n", addr_text);
        return DBG_OK;
    }
    dbg_out(dbg, DBG_OUT_NORMAL, "%s %s\n", addr_text, name);
    if (dbg_source_at(dbg, addr, &source))
        dbg_out(dbg, DBG_OUT_NORMAL, "  %s(%u)%s\n", source.file, source.line,
                source.file_found ? "" : " [file not found, see .srcpath]");
    return DBG_OK;
}

static const char *file_name(const char *path)
{
    const char *cursor;
    const char *name;

    name = path;
    for (cursor = path; *cursor; cursor++)
        if (*cursor == '/' || *cursor == '\\' || *cursor == ':')
            name = cursor + 1;
    return name;
}

static void print_find_match(dbg_ctx *dbg, const dbg_find_match *match)
{
    const char *name;
    const char *dot;
    int         module_len;

    name = file_name(match->file);
    dot = strrchr(name, '.');
    module_len = dot && dot != name ? (int)(dot - name) : (int)strlen(name);
    if (match->is_pe)
        dbg_out(dbg, DBG_OUT_NORMAL, "lds %.*s %" PRIx64 "        ; %s offset 0x%" PRIx64
                " rva 0x%x%s\n", module_len, name, match->base, name, match->offset, match->rva,
                match->aligned ? "" : " (unaligned base)");
    else
        dbg_out(dbg, DBG_OUT_NORMAL, "lds %.*s %" PRIx64 "        ; %s offset 0x%" PRIx64
                " (not a PE image)\n", module_len, name, match->base, name, match->offset);
}

static dbg_status eval_word(dbg_ctx *dbg, cmd_args *args, uint64_t *out)
{
    cmd_args   word_args;
    char       word[128];
    size_t     len;
    dbg_status status;

    len = 0;
    cmd_skip_ws(args);
    while (args->cursor[len] && args->cursor[len] != ' ' && args->cursor[len] != '\t')
        len++;
    if (len >= sizeof word)
        return cmd_fail(args, NULL, "address expression too long");
    memcpy(word, args->cursor, len);
    word[len] = '\0';
    word_args.line = word;
    word_args.cursor = word;
    word_args.err_at = NULL;
    word_args.err[0] = '\0';
    status = expr_eval(dbg, &word_args, out);
    if (status == DBG_OK && !cmd_at_end(&word_args))
        status = cmd_fail(&word_args, NULL, "unexpected '%s'", word_args.cursor);
    if (status != DBG_OK) {
        if (word_args.err[0]) {
            args->err_at = args->cursor + (word_args.err_at - word);
            memcpy(args->err, word_args.err, sizeof args->err);
        }
        return status;
    }
    args->cursor += len;
    return DBG_OK;
}

static const char *image_format_name(dbg_image_format format)
{
    switch (format) {
        case DBG_IMAGE_PE:
            return "PE";
        case DBG_IMAGE_TE:
            return "TE";
        case DBG_IMAGE_ELF:
            return "ELF";
        case DBG_IMAGE_NONE:
            break;
    }
    return "?";
}

static void describe_image(const dbg_image *image, char *detail, size_t cap)
{
    size_t   len;
    uint32_t index;

    len = 0;
    detail[0] = '\0';
    if (image->debug_path[0])
        len += (size_t)snprintf(detail + len, cap - len, ", pdb %s", image->debug_path);
    else if (image->file[0])
        len += (size_t)snprintf(detail + len, cap - len, ", file %s", image->file);
    if (image->build_id_len && len < cap)
        len += (size_t)snprintf(detail + len, cap - len, ", build-id ");
    for (index = 0; index < image->build_id_len && len + 3 < cap; index++)
        len += (size_t)snprintf(detail + len, cap - len, "%02x", image->build_id[index]);
    if (image->header != image->base && len < cap)
        snprintf(detail + len, cap - len, ", header at %" PRIx64, image->header);
}

static dbg_status find_image(dbg_ctx *dbg, uint64_t addr)
{
    dbg_image  image;
    char       detail[DBG_FIND_PATH * 2];
    dbg_status status;

    status = dbg_find_image(dbg, addr, &image);
    if (status != DBG_OK)
        return status;
    if (image.format == DBG_IMAGE_NONE) {
        dbg_out(dbg, DBG_OUT_NORMAL,
                "no image header found from %" PRIx64 " down to %" PRIx64
                "; try find <addr> <ext> for a byte search\n", addr, image.lowest);
        return DBG_OK;
    }
    if (!image.contains) {
        dbg_out(dbg, DBG_OUT_NORMAL,
                "%" PRIx64 " is not inside an image: the %s image at %" PRIx64 " ends at %"
                PRIx64 "\n", addr, image_format_name(image.format), image.base,
                image.base + image.size);
        return DBG_OK;
    }
    describe_image(&image, detail, sizeof detail);
    if (image.name[0])
        dbg_out(dbg, DBG_OUT_NORMAL, "lds %s %" PRIx64 "        ; %s image %" PRIx64 "-%" PRIx64
                "%s\n", image.name, image.base, image_format_name(image.format), image.base,
                image.base + image.size, detail);
    else
        dbg_out(dbg, DBG_OUT_NORMAL,
                "%s image %" PRIx64 "-%" PRIx64 "%s, but no debug record names it and no file "
                "in the executable folders matches it\n  load it with lds <file> %" PRIx64 "\n",
                image_format_name(image.format), image.base, image.base + image.size, detail,
                image.base);
    return DBG_OK;
}

static dbg_status cmd_find_module(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    dbg_find_match *matches;
    char            extension[32];
    char            dirs[MAX_LINE];
    const char     *extension_at;
    uint64_t        addr;
    uint64_t        len;
    int             count;
    int             files;
    int             shown;
    int             pass;
    int             index;
    dbg_status      status;

    (void)arg;
    len = 0x40;
    dirs[0] = '\0';
    count = 0;
    files = 0;
    status = eval_word(dbg, args, &addr);
    if (status != DBG_OK)
        return status;
    if (cmd_at_end(args))
        return find_image(dbg, addr);
    cmd_skip_ws(args);
    extension_at = args->cursor;
    status = arg_path(args, extension, sizeof extension);
    if (status != DBG_OK)
        return status;
    if (!extension[0])
        return cmd_fail(args, extension_at, "expected a file extension, like .efi");
    cmd_skip_ws(args);
    if ((*args->cursor == 'l' || *args->cursor == 'L') &&
        isxdigit((unsigned char)args->cursor[1])) {
        args->cursor++;
        status = expr_eval(dbg, args, &len);
        if (status != DBG_OK)
            return status;
    }
    if (!cmd_at_end(args)) {
        status = arg_path(args, dirs, sizeof dirs);
        if (status == DBG_OK)
            status = arg_end(args);
        if (status != DBG_OK)
            return status;
    }
    if (len == 0 || len > 0x100)
        return cmd_fail(args, NULL, "length must be 1 to 0x100 bytes");

    matches = malloc(MAX_FIND_MATCHES * sizeof *matches);
    if (!matches)
        return DBG_E_NOMEM;
    status = dbg_find(dbg, addr, (uint32_t)len, extension, dirs, matches, MAX_FIND_MATCHES,
                      &count, &files);
    if (status == DBG_OK) {
        shown = count < MAX_FIND_MATCHES ? count : MAX_FIND_MATCHES;
        for (pass = 0; pass < 2; pass++)
            for (index = 0; index < shown; index++)
                if (matches[index].aligned == (pass == 0))
                    print_find_match(dbg, &matches[index]);
        if (count > shown)
            dbg_out(dbg, DBG_OUT_NORMAL, "... %d more\n", count - shown);
        dbg_out(dbg, DBG_OUT_NORMAL, "%d match%s in %d file%s\n", count, count == 1 ? "" : "es",
                files, files == 1 ? "" : "s");
    }
    free(matches);
    return status;
}

typedef struct stack_listing {
    dbg_ctx *dbg;
    unsigned mode;
    bool     args;
} stack_listing;

static void print_param(void *user, const dbg_local *local)
{
    dbg_out((dbg_ctx *)user, DBG_OUT_NORMAL, "      %-24s %-20s = %s\n", local->type, local->name,
            local->value);
}

static void home_space(dbg_ctx *dbg, const dbg_frame *frame, char *buf, size_t cap)
{
    uint64_t slots[4];
    char     text[4][24];
    uint32_t done;
    uint32_t index;

    done = 0;
    if (!frame->have_cfa ||
        dbg_read_mem(dbg, EM_SPACE_VIRT, frame->cfa, slots, sizeof slots, &done) != DBG_OK ||
        done != sizeof slots) {
        snprintf(buf, cap, "%-71s", "(not available)");
        return;
    }
    for (index = 0; index < 4; index++)
        hex64(text[index], sizeof text[index], slots[index]);
    snprintf(buf, cap, "%s %s %s %s", text[0], text[1], text[2], text[3]);
}

static bool print_frame(void *user, const dbg_frame *frame)
{
    stack_listing *listing;
    char           site[160];
    char           sp_text[24];
    char           return_text[24];
    char           args[96];

    listing = user;
    if (!dbg_sym_format(listing->dbg, frame->pc, site, sizeof site))
        snprintf(site, sizeof site, "0x%016" PRIx64, frame->pc);
    if (listing->mode == STACK_CALLS) {
        dbg_out(listing->dbg, DBG_OUT_NORMAL, "%02x %s\n", frame->number, site);
    } else {
        hex64(sp_text, sizeof sp_text, frame->sp);
        if (frame->have_return)
            hex64(return_text, sizeof return_text, frame->return_addr);
        else
            snprintf(return_text, sizeof return_text, "????????`????????");
        if (listing->args) {
            home_space(listing->dbg, frame, args, sizeof args);
            dbg_out(listing->dbg, DBG_OUT_NORMAL, "%02x %s %s : %s : %s\n", frame->number,
                    sp_text, return_text, args, site);
        } else {
            dbg_out(listing->dbg, DBG_OUT_NORMAL, "%02x %s %s %s\n", frame->number, sp_text,
                    return_text, site);
        }
    }
    if (listing->mode == STACK_VERBOSE)
        dbg_frame_params(listing->dbg, frame, print_param, listing->dbg);
    if (!frame->have_cfa)
        dbg_out(listing->dbg, DBG_OUT_NORMAL,
                "   (no unwind information here: load the module's symbols with lds)\n");
    return true;
}

static dbg_status cmd_stack(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    stack_listing listing;
    uint64_t      count;
    dbg_status    status;

    count = MAX_STACK_FRAMES;
    if (!cmd_at_end(args)) {
        status = expr_eval(dbg, args, &count);
        if (status == DBG_OK)
            status = arg_end(args);
        if (status != DBG_OK)
            return status;
        if (count == 0 || count > MAX_STACK_FRAMES)
            return cmd_fail(args, NULL, "frame count must be 1 to 0x%x", MAX_STACK_FRAMES);
    }
    listing.dbg = dbg;
    listing.mode = (unsigned)arg;
    listing.args = arg == STACK_VERBOSE && dbg_get_cpu_mode(dbg) == DBG_MODE_LONG64;
    if (arg == STACK_CALLS)
        dbg_out(dbg, DBG_OUT_NORMAL, " # Call Site\n");
    else if (listing.args)
        dbg_out(dbg, DBG_OUT_NORMAL, " # Child-SP          RetAddr           : Args to Child"
                "                                                           : Call Site\n");
    else
        dbg_out(dbg, DBG_OUT_NORMAL, " # Child-SP          RetAddr           Call Site\n");
    return dbg_stack_walk(dbg, (uint32_t)count, print_frame, &listing);
}

static dbg_status cmd_frame(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    stack_listing listing;
    dbg_frame     frame;
    uint64_t      number;
    dbg_status    status;

    (void)arg;
    if (!cmd_at_end(args)) {
        status = expr_eval(dbg, args, &number);
        if (status == DBG_OK)
            status = arg_end(args);
        if (status != DBG_OK)
            return status;
        if (number >= MAX_STACK_FRAMES || dbg_set_frame(dbg, (uint32_t)number) != DBG_OK)
            return cmd_fail(args, NULL, "no frame %" PRIx64 " (see k)", number);
    }
    status = dbg_frame_info(dbg, &frame);
    if (status != DBG_OK)
        return status;
    listing.dbg = dbg;
    listing.mode = STACK_PLAIN;
    listing.args = false;
    print_frame(&listing, &frame);
    return DBG_OK;
}

static dbg_status cmd_dx(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    (void)arg;
    return value_dx(dbg, args);
}

static dbg_status cmd_dv(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    dbg_status status;

    (void)arg;
    status = arg_end(args);
    if (status != DBG_OK)
        return status;
    return value_dv(dbg);
}

typedef struct symbol_listing {
    dbg_ctx *dbg;
    int      printed;
} symbol_listing;

static bool print_symbol(void *user, const char *module, const char *name, uint64_t addr)
{
    symbol_listing *listing;
    char            addr_text[24];

    listing = user;
    if (listing->printed >= MAX_SYMBOL_LINES)
        return true;
    hex64(addr_text, sizeof addr_text, addr);
    dbg_out(listing->dbg, DBG_OUT_NORMAL, "%s %s!%s\n", addr_text, module, name);
    listing->printed++;
    return true;
}

static dbg_status cmd_x(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    symbol_listing listing;
    char           pattern[256];
    const char    *pattern_at;
    int            count;
    dbg_status     status;

    (void)arg;
    cmd_skip_ws(args);
    pattern_at = args->cursor;
    status = arg_path(args, pattern, sizeof pattern);
    if (status == DBG_OK)
        status = arg_end(args);
    if (status != DBG_OK)
        return status;
    if (!pattern[0])
        return cmd_fail(args, pattern_at, "expected a pattern, like module!func*");
    if (!dbg_module_count(dbg)) {
        dbg_out(dbg, DBG_OUT_NORMAL, "no symbols loaded (use lds)\n");
        return DBG_OK;
    }
    listing.dbg = dbg;
    listing.printed = 0;
    count = dbg_sym_enum(dbg, pattern, print_symbol, &listing);
    if (count > listing.printed)
        dbg_out(dbg, DBG_OUT_NORMAL, "... %d more, narrow the pattern\n",
                count - listing.printed);
    dbg_out(dbg, DBG_OUT_NORMAL, "%d symbol%s\n", count, count == 1 ? "" : "s");
    return DBG_OK;
}

static dbg_status cmd_path(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    char        dirs[MAX_LINE];
    const char *kind;
    dbg_status  status;

    kind = path_kinds[arg];
    if (!cmd_at_end(args)) {
        status = arg_path(args, dirs, sizeof dirs);
        if (status == DBG_OK)
            status = arg_end(args);
        if (status != DBG_OK)
            return status;
        if (arg == PATH_SOURCE)
            status = dbg_set_src_path(dbg, dirs);
        else if (arg == PATH_EXECUTABLE)
            status = dbg_set_exe_path(dbg, dirs);
        else
            status = dbg_set_sym_path(dbg, dirs);
        if (status != DBG_OK)
            return status;
    }
    if (arg == PATH_SOURCE)
        dbg_out(dbg, DBG_OUT_NORMAL, "%s path: %s\n", kind, dbg_get_src_path(dbg));
    else if (arg == PATH_EXECUTABLE)
        dbg_out(dbg, DBG_OUT_NORMAL, "%s path: %s\n", kind, dbg_get_exe_path(dbg));
    else
        dbg_out(dbg, DBG_OUT_NORMAL, "%s path: %s\n", kind, dbg_get_sym_path(dbg));
    return DBG_OK;
}

static dbg_status cmd_help(dbg_ctx *dbg, cmd_args *args, uintptr_t arg);

static const cmd_def commands[] = {
    { "g",           cmd_go,         0,                       CMD_STOPPED,
      "g",                          "continue" },
    { "t",           cmd_step,       STEP_INTO,               CMD_STOPPED | CMD_REPEAT,
      "t",                          "step into (one instruction)" },
    { "p",           cmd_step,       STEP_OVER,               CMD_STOPPED | CMD_REPEAT,
      "p",                          "step over calls, int, syscall, rep" },
    { "gu",          cmd_step,       STEP_OUT,                CMD_STOPPED,
      "gu",                         "step out: run to the return address of this function" },
    { "ts",          cmd_step,       STEP_LINE_INTO,          CMD_STOPPED | CMD_REPEAT,
      "ts",                         "step into, one source line" },
    { "ps",          cmd_step,       STEP_LINE_OVER,          CMD_STOPPED | CMD_REPEAT,
      "ps",                         "step over, one source line" },
    { "pc",          cmd_step,       STEP_TO_CALL,            CMD_STOPPED | CMD_REPEAT,
      "pc",                         "run to the next call instruction" },
    { "ph",          cmd_step,       STEP_TO_BRANCH,          CMD_STOPPED | CMD_REPEAT,
      "ph",                         "run to the next branch, call or return" },
    { "l+t",         cmd_source_mode, 1,                      0,
      "l+t",                        "t, p, F10 and F11 step by source line" },
    { "l-t",         cmd_source_mode, 0,                      0,
      "l-t",                        "t, p, F10 and F11 step by instruction" },
    { "u",           cmd_unasm,      0,                       CMD_TARGET | CMD_REPEAT,
      "u [addr] [L count]",         "disassemble" },
    { "pause",       cmd_pause,      0,                       CMD_TARGET,
      "pause",                      "pause the running target" },
    { "bp",          cmd_bp,         0,                       0,
      "bp <addr>",                  "add an execute breakpoint" },
    { "ba",          cmd_ba,         0,                       0,
      "ba <e|r|w|a> <size> <addr>", "add a data / hardware breakpoint" },
    { "bl",          cmd_bl,         0,                       0,
      "bl",                         "list breakpoints" },
    { "bc",          cmd_bc,         0,                       0,
      "bc <n...|*>",                "clear breakpoints" },
    { "bd",          cmd_bc,         1,                       0,
      "bd <n...|*>",                "disable breakpoints" },
    { "be",          cmd_bc,         2,                       0,
      "be <n...|*>",                "enable breakpoints" },
    { "r",           cmd_reg,        0,                       CMD_STOPPED,
      "r [reg[=expr]]",             "show registers, or set one" },
    { "db",          cmd_dump,       MEM_ARG(1, FMT_HEX, 0),     CMD_TARGET | CMD_REPEAT,
      "db [range]",                 "dump bytes" },
    { "dw",          cmd_dump,       MEM_ARG(2, FMT_HEX, 0),     CMD_TARGET | CMD_REPEAT,
      "dw [range]",                 "dump words" },
    { "dd",          cmd_dump,       MEM_ARG(4, FMT_HEX, 0),     CMD_TARGET | CMD_REPEAT,
      "dd [range]",                 "dump dwords" },
    { "dq",          cmd_dump,       MEM_ARG(8, FMT_HEX, 0),     CMD_TARGET | CMD_REPEAT,
      "dq [range]",                 "dump qwords" },
    { "da",          cmd_dump,       MEM_ARG(1, FMT_ASCII, 0),   CMD_TARGET,
      "da [range]",                 "dump an ASCII string" },
    { "du",          cmd_dump,       MEM_ARG(2, FMT_UNICODE, 0), CMD_TARGET,
      "du [range]",                 "dump a UTF-16 string" },
    { "!db",         cmd_dump,       MEM_ARG(1, FMT_HEX, 1),     CMD_TARGET | CMD_REPEAT,
      "!db [range]",                "dump bytes at a physical address" },
    { "!dw",         cmd_dump,       MEM_ARG(2, FMT_HEX, 1),     CMD_TARGET | CMD_REPEAT,
      "!dw [range]",                "dump words at a physical address" },
    { "!dd",         cmd_dump,       MEM_ARG(4, FMT_HEX, 1),     CMD_TARGET | CMD_REPEAT,
      "!dd [range]",                "dump dwords at a physical address" },
    { "!dq",         cmd_dump,       MEM_ARG(8, FMT_HEX, 1),     CMD_TARGET | CMD_REPEAT,
      "!dq [range]",                "dump qwords at a physical address" },
    { "eb",          cmd_edit,       MEM_ARG(1, FMT_HEX, 0),     CMD_TARGET,
      "eb <addr> <values>",         "write bytes" },
    { "ew",          cmd_edit,       MEM_ARG(2, FMT_HEX, 0),     CMD_TARGET,
      "ew <addr> <values>",         "write words" },
    { "ed",          cmd_edit,       MEM_ARG(4, FMT_HEX, 0),     CMD_TARGET,
      "ed <addr> <values>",         "write dwords" },
    { "eq",          cmd_edit,       MEM_ARG(8, FMT_HEX, 0),     CMD_TARGET,
      "eq <addr> <values>",         "write qwords" },
    { "!eb",         cmd_edit,       MEM_ARG(1, FMT_HEX, 1),     CMD_TARGET,
      "!eb <addr> <values>",        "write bytes at a physical address" },
    { "!ew",         cmd_edit,       MEM_ARG(2, FMT_HEX, 1),     CMD_TARGET,
      "!ew <addr> <values>",        "write words at a physical address" },
    { "!ed",         cmd_edit,       MEM_ARG(4, FMT_HEX, 1),     CMD_TARGET,
      "!ed <addr> <values>",        "write dwords at a physical address" },
    { "!eq",         cmd_edit,       MEM_ARG(8, FMT_HEX, 1),     CMD_TARGET,
      "!eq <addr> <values>",        "write qwords at a physical address" },
    { "!vtop",       cmd_vtop,       0,                       CMD_TARGET,
      "!vtop <addr>",               "translate a virtual address" },
    { "?",           cmd_eval,       0,                       0,
      "? <expr>",                   "evaluate an expression" },
    { ".connect",    cmd_connect,    0,                       0,
      ".connect [host[:port]]",     "connect to a stub (default 127.0.0.1:4242)" },
    { ".disconnect", cmd_disconnect, 0,                       CMD_TARGET,
      ".disconnect",                "close the connection" },
    { ".monitor",    cmd_monitor,    0,                       CMD_TARGET,
      ".monitor <text>",            "send a target-specific command" },
    { "lds",         cmd_lds,        0,                       0,
      "lds <file> <base|start end>", "load module symbols at base, or find it in a range" },
    { "lm",          cmd_lm,         0,                       0,
      "lm",                         "list modules with symbols" },
    { "ln",          cmd_ln,         0,                       0,
      "ln [addr]",                  "nearest symbol and source line" },
    { "k",           cmd_stack,      STACK_PLAIN,             CMD_STOPPED,
      "k [frames]",                 "call stack: Child-SP, return address, call site" },
    { "kc",          cmd_stack,      STACK_CALLS,             CMD_STOPPED,
      "kc [frames]",                "call stack: call sites only" },
    { "kv",          cmd_stack,      STACK_VERBOSE,           CMD_STOPPED,
      "kv [frames]",                "call stack with home-space args and parameters" },
    { ".frame",      cmd_frame,      0,                       CMD_STOPPED,
      ".frame [n]",                 "show or select the frame used by dv, dx and Locals" },
    { "dv",          cmd_dv,         0,                       CMD_STOPPED,
      "dv",                         "locals and parameters of the current function" },
    { "dx",          cmd_dx,         0,                       CMD_TARGET,
      "dx <expr>",                  "show a variable: name, a.b, p->b, a[n], *p, &a" },
    { "x",           cmd_x,          0,                       0,
      "x [module!]pattern",         "list symbols matching * and ? (any case)" },
    { "find",        cmd_find_module, 0,                      CMD_TARGET,
      "find <addr> [<ext> [L<len>] [dir]]", "find the image holding addr (header walk), or "
                                            "search files for its bytes" },
    { ".sympath",    cmd_path,       PATH_SYMBOL,             0,
      ".sympath [\"dir;dir\"]",       "show or set the symbol folders" },
    { ".srcpath",    cmd_path,       PATH_SOURCE,             0,
      ".srcpath [\"dir;dir\"]",       "show or set the source folders" },
    { ".exepath",    cmd_path,       PATH_EXECUTABLE,         0,
      ".exepath [\"dir;dir\"]",       "show or set the executable (module) folders" },
    { "help",        cmd_help,       0,                       0,
      "help",                       "this list" },
};

static dbg_status cmd_help(dbg_ctx *dbg, cmd_args *args, uintptr_t arg)
{
    size_t index;

    (void)args;
    (void)arg;
    for (index = 0; index < sizeof commands / sizeof commands[0]; index++)
        dbg_out(dbg, DBG_OUT_NORMAL, "  %-28s %s\n", commands[index].usage, commands[index].help);
    dbg_out(dbg, DBG_OUT_NORMAL,
            "Expressions: numbers are hex (0n10 decimal, 0y101 binary), registers (rax, @eax),\n"
            "  + - * / %% << >> & | ^ == != < > ~ !, poi(addr) by() wo() dwo() qwo(),\n"
            "  symbols as function, module!function or module.\n"
            "Ranges: <addr> L<count> or <start> <end>. ';' separates commands; an empty line\n"
            "  repeats the last step or dump.\n");
    return DBG_OK;
}

static const cmd_def *cmd_find(const char *name, size_t len)
{
    size_t index;

    for (index = 0; index < sizeof commands / sizeof commands[0]; index++)
        if (strlen(commands[index].name) == len && !strncmp(commands[index].name, name, len))
            return &commands[index];
    return NULL;
}

static void report(dbg_ctx *dbg, const cmd_args *args)
{
    int column;

    column = 2 + (int)(args->err_at - args->line);
    dbg_out(dbg, DBG_OUT_ERROR, "%*s^ %s\n", column, "", args->err);
}

static dbg_status exec_one(dbg_ctx *dbg, const char *line, const char *cmd)
{
    const cmd_def *def;
    const char    *name;
    char           lower_name[16];
    cmd_args       args;
    size_t         len;
    size_t         index;
    dbg_status     status;

    args.line = line;
    args.cursor = cmd;
    args.err_at = NULL;
    args.err[0] = '\0';
    if (cmd_at_end(&args))
        return DBG_OK;

    name = args.cursor;
    if (*args.cursor == '?') {
        args.cursor++;
    } else {
        if (*args.cursor == '!' || *args.cursor == '.')
            args.cursor++;
        while (isalnum((unsigned char)*args.cursor) || *args.cursor == '_')
            args.cursor++;
        if (args.cursor == name + 1 && (name[0] == 'l' || name[0] == 'L') &&
            (*args.cursor == '+' || *args.cursor == '-') && isalpha((unsigned char)args.cursor[1])) {
            args.cursor++;
            while (isalnum((unsigned char)*args.cursor))
                args.cursor++;
        }
    }
    len = (size_t)(args.cursor - name);
    for (index = 0; index < len && index < sizeof lower_name - 1; index++)
        lower_name[index] = (char)tolower((unsigned char)name[index]);
    lower_name[index] = '\0';

    def = len < sizeof lower_name ? cmd_find(lower_name, len) : NULL;
    if (!def) {
        cmd_fail(&args, name, "unknown command '%.*s' (try help)", (int)(len ? len : 1), name);
        report(dbg, &args);
        return DBG_E_BADARG;
    }
    if (*args.cursor && *args.cursor != ' ' && *args.cursor != '\t' && def->name[0] != '?') {
        cmd_fail(&args, NULL, "expected a space after '%s'", def->name);
        report(dbg, &args);
        return DBG_E_BADARG;
    }
    if ((def->flags & (CMD_TARGET | CMD_STOPPED)) &&
        dbg_get_state(dbg) == DBG_STATE_DISCONNECTED) {
        dbg_out(dbg, DBG_OUT_ERROR, "%s: not connected (use .connect)\n", def->name);
        return DBG_E_DISCONNECTED;
    }
    if ((def->flags & CMD_STOPPED) && dbg_get_state(dbg) != DBG_STATE_STOPPED) {
        dbg_out(dbg, DBG_OUT_ERROR, "%s: the target is running (use pause)\n", def->name);
        return DBG_E_RUNNING;
    }

    status = def->fn(dbg, &args, def->arg);
    if (status != DBG_OK) {
        if (args.err[0])
            report(dbg, &args);
        else
            dbg_out(dbg, DBG_OUT_ERROR, "%s: %s\n", def->name, dbg_status_str(status));
    }
    dbg->repeat = (status == DBG_OK && (def->flags & CMD_REPEAT)) ? def->name : NULL;
    return status;
}

static char *find_separator(char *cmd)
{
    bool quoted;

    quoted = false;
    for (; *cmd; cmd++) {
        if (*cmd == '"')
            quoted = !quoted;
        else if (*cmd == ';' && !quoted)
            return cmd;
    }
    return NULL;
}

dbg_status dbg_exec(dbg_ctx *dbg, const char *line)
{
    char       buf[MAX_LINE];
    char      *cmd;
    char      *semicolon;
    size_t     len;
    dbg_status status;

    len = strlen(line);
    status = DBG_OK;
    if (len >= sizeof buf) {
        dbg_out(dbg, DBG_OUT_ERROR, "command line too long (max %d characters)\n", MAX_LINE - 1);
        return DBG_E_BADARG;
    }
    while (len && isspace((unsigned char)line[len - 1]))
        len--;
    memcpy(buf, line, len);
    buf[len] = '\0';

    cmd = buf;
    while (*cmd == ' ' || *cmd == '\t')
        cmd++;
    if (!*cmd) {
        if (!dbg->repeat)
            return DBG_OK;
        strcpy(buf, dbg->repeat);
    }

    dbg_out(dbg, DBG_OUT_ECHO, "> %s\n", buf);
    for (cmd = buf;; cmd = semicolon + 1) {
        semicolon = find_separator(cmd);
        if (semicolon)
            *semicolon = '\0';
        status = exec_one(dbg, buf, cmd);
        if (status != DBG_OK || !semicolon)
            break;
    }
    return status;
}
