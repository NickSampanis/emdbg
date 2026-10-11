#include "cmd.h"

#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define R_CORE(n, f, sz, off) { n, EM_RB_X86_CORE, sz, (uint16_t)(offsetof(em_x86_regs, core.f) + (off)) }
#define R_CTRL(n, f)          { n, EM_RB_X86_CTRL, 8, (uint16_t)offsetof(em_x86_regs, ctrl.f) }
#define R_SEL(n, f)           { n, EM_RB_X86_SEG, 2, (uint16_t)offsetof(em_x86_regs, seg.f.selector) }
#define R_BASE(n, f)          { n, EM_RB_X86_SEG, 8, (uint16_t)offsetof(em_x86_regs, seg.f.base) }

#define R_GPR(f, n64, n32, n16, n8) \
    R_CORE(n64, f, 8, 0), R_CORE(n32, f, 4, 0), R_CORE(n16, f, 2, 0), R_CORE(n8, f, 1, 0)

static const reg_def reg_table[] = {
    R_GPR(rax, "rax", "eax", "ax", "al"),
    R_GPR(rcx, "rcx", "ecx", "cx", "cl"),
    R_GPR(rdx, "rdx", "edx", "dx", "dl"),
    R_GPR(rbx, "rbx", "ebx", "bx", "bl"),
    R_GPR(rsp, "rsp", "esp", "sp", "spl"),
    R_GPR(rbp, "rbp", "ebp", "bp", "bpl"),
    R_GPR(rsi, "rsi", "esi", "si", "sil"),
    R_GPR(rdi, "rdi", "edi", "di", "dil"),
    R_GPR(r8,  "r8",  "r8d",  "r8w",  "r8b"),
    R_GPR(r9,  "r9",  "r9d",  "r9w",  "r9b"),
    R_GPR(r10, "r10", "r10d", "r10w", "r10b"),
    R_GPR(r11, "r11", "r11d", "r11w", "r11b"),
    R_GPR(r12, "r12", "r12d", "r12w", "r12b"),
    R_GPR(r13, "r13", "r13d", "r13w", "r13b"),
    R_GPR(r14, "r14", "r14d", "r14w", "r14b"),
    R_GPR(r15, "r15", "r15d", "r15w", "r15b"),
    R_CORE("ah", rax, 1, 1), R_CORE("ch", rcx, 1, 1),
    R_CORE("dh", rdx, 1, 1), R_CORE("bh", rbx, 1, 1),
    R_CORE("rip", rip, 8, 0), R_CORE("eip", rip, 4, 0), R_CORE("ip", rip, 2, 0),
    R_CORE("rflags", rflags, 8, 0), R_CORE("eflags", rflags, 4, 0), R_CORE("efl", rflags, 4, 0),
    R_CTRL("cr0", cr0), R_CTRL("cr2", cr2), R_CTRL("cr3", cr3), R_CTRL("cr4", cr4),
    R_CTRL("cr8", cr8), R_CTRL("efer", efer), R_CTRL("xcr0", xcr0),
    R_CTRL("dr0", dr0), R_CTRL("dr1", dr1), R_CTRL("dr2", dr2), R_CTRL("dr3", dr3),
    R_CTRL("dr6", dr6), R_CTRL("dr7", dr7),
    R_SEL("cs", cs), R_SEL("ss", ss), R_SEL("ds", ds), R_SEL("es", es),
    R_SEL("fs", fs), R_SEL("gs", gs), R_SEL("ldtr", ldtr), R_SEL("tr", tr),
    R_BASE("fsbase", fs), R_BASE("gsbase", gs),
    R_BASE("gdtr", gdtr), R_BASE("idtr", idtr),
};

static int name_eq(const char *text, size_t text_len, const char *name)
{
    size_t index;

    for (index = 0; index < text_len; index++)
        if (!name[index] || tolower((unsigned char)text[index]) != name[index])
            return 0;
    return name[text_len] == '\0';
}

const reg_def *reg_find(const char *name, size_t len)
{
    size_t index;

    for (index = 0; index < sizeof reg_table / sizeof reg_table[0]; index++)
        if (name_eq(name, len, reg_table[index].name))
            return &reg_table[index];
    return NULL;
}

uint64_t reg_get(const em_x86_regs *regs, const reg_def *reg)
{
    uint64_t value;

    value = 0;
    memcpy(&value, (const uint8_t *)regs + reg->offset, reg->size);
    return value;
}

void reg_set(em_x86_regs *regs, const reg_def *reg, uint64_t value)
{
    memcpy((uint8_t *)regs + reg->offset, &value, reg->size);
}

dbg_status cmd_fail(cmd_args *args, const char *at, const char *fmt, ...)
{
    va_list arg_list;

    args->err_at = at ? at : args->cursor;
    va_start(arg_list, fmt);
    vsnprintf(args->err, sizeof args->err, fmt, arg_list);
    va_end(arg_list);
    return DBG_E_BADARG;
}

void cmd_skip_ws(cmd_args *args)
{
    while (*args->cursor == ' ' || *args->cursor == '\t')
        args->cursor++;
}

int cmd_at_end(cmd_args *args)
{
    cmd_skip_ws(args);
    return *args->cursor == '\0';
}

static int is_word_char(char ch)
{
    return isalnum((unsigned char)ch) || ch == '_' || ch == '`';
}

static int digit_value(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    ch = (char)tolower((unsigned char)ch);
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return 99;
}

static int parse_number(const char *text, size_t len, uint64_t *out)
{
    uint64_t value;
    unsigned radix;
    size_t   index;
    int      digits;
    int      digit;

    value = 0;
    radix = 16;
    index = 0;
    digits = 0;
    if (len > 2 && text[0] == '0') {
        switch (tolower((unsigned char)text[1])) {
            case 'x':
                radix = 16;
                index = 2;
                break;
            case 'n':
                radix = 10;
                index = 2;
                break;
            case 'y':
                radix = 2;
                index = 2;
                break;
            case 't':
                radix = 8;
                index = 2;
                break;
        }
    }
    for (; index < len; index++) {
        if (text[index] == '`')
            continue;
        digit = digit_value(text[index]);
        if (digit >= (int)radix)
            return 0;
        value = value * radix + (unsigned)digit;
        digits++;
    }
    if (!digits)
        return 0;
    *out = value;
    return 1;
}

typedef enum binop {
    OP_NONE, OP_OR, OP_XOR, OP_AND, OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE,
    OP_SHL, OP_SHR, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD,
} binop;

static binop peek_binop(const char *text, int *len)
{
    *len = 2;
    if (text[0] == '=' && text[1] == '=')
        return OP_EQ;
    if (text[0] == '!' && text[1] == '=')
        return OP_NE;
    if (text[0] == '<' && text[1] == '=')
        return OP_LE;
    if (text[0] == '>' && text[1] == '=')
        return OP_GE;
    if (text[0] == '<' && text[1] == '<')
        return OP_SHL;
    if (text[0] == '>' && text[1] == '>')
        return OP_SHR;
    *len = 1;
    switch (text[0]) {
        case '|':
            return OP_OR;
        case '^':
            return OP_XOR;
        case '&':
            return OP_AND;
        case '<':
            return OP_LT;
        case '>':
            return OP_GT;
        case '+':
            return OP_ADD;
        case '-':
            return OP_SUB;
        case '*':
            return OP_MUL;
        case '/':
            return OP_DIV;
        case '%':
            return OP_MOD;
    }
    return OP_NONE;
}

static int precedence(binop op)
{
    switch (op) {
        case OP_OR:
            return 1;
        case OP_XOR:
            return 2;
        case OP_AND:
            return 3;
        case OP_EQ:
        case OP_NE:
            return 4;
        case OP_LT:
        case OP_LE:
        case OP_GT:
        case OP_GE:
            return 5;
        case OP_SHL:
        case OP_SHR:
            return 6;
        case OP_ADD:
        case OP_SUB:
            return 7;
        case OP_MUL:
        case OP_DIV:
        case OP_MOD:
            return 8;
        case OP_NONE:
            break;
    }
    return 0;
}

static uint64_t apply(binop op, uint64_t left, uint64_t right)
{
    switch (op) {
        case OP_OR:
            return left | right;
        case OP_XOR:
            return left ^ right;
        case OP_AND:
            return left & right;
        case OP_EQ:
            return left == right;
        case OP_NE:
            return left != right;
        case OP_LT:
            return left < right;
        case OP_LE:
            return left <= right;
        case OP_GT:
            return left > right;
        case OP_GE:
            return left >= right;
        case OP_SHL:
            return left << (right & 63);
        case OP_SHR:
            return left >> (right & 63);
        case OP_ADD:
            return left + right;
        case OP_SUB:
            return left - right;
        case OP_MUL:
            return left * right;
        case OP_DIV:
            return left / right;
        case OP_MOD:
            return left % right;
        case OP_NONE:
            break;
    }
    return 0;
}

static unsigned mem_fn_size(dbg_ctx *dbg, const char *name, size_t len)
{
    const em_x86_regs *regs;

    if (name_eq(name, len, "by"))
        return 1;
    if (name_eq(name, len, "wo"))
        return 2;
    if (name_eq(name, len, "dwo"))
        return 4;
    if (name_eq(name, len, "qwo"))
        return 8;
    if (name_eq(name, len, "poi")) {
        regs = dbg_regs(dbg);
        if (regs && !(EM_SEG_L(regs->seg.cs.attr) && (regs->ctrl.efer & (1u << 10))))
            return 4;
        return 8;
    }
    return 0;
}

static dbg_status parse_binary(dbg_ctx *dbg, cmd_args *args, int min_prec, uint64_t *out);

static dbg_status parse_primary(dbg_ctx *dbg, cmd_args *args, uint64_t *out)
{
    const em_x86_regs *regs;
    const reg_def     *reg;
    const char        *start;
    const char        *word;
    const char        *next;
    size_t             len;
    unsigned           size;
    uint64_t           addr;
    uint64_t           value;
    uint32_t           done;
    int                force_reg;
    dbg_status         status;

    value = 0;
    force_reg = 0;
    cmd_skip_ws(args);
    start = args->cursor;
    if (*args->cursor == '(') {
        args->cursor++;
        status = parse_binary(dbg, args, 1, out);
        if (status != DBG_OK)
            return status;
        cmd_skip_ws(args);
        if (*args->cursor != ')')
            return cmd_fail(args, NULL, "expected ')'");
        args->cursor++;
        return DBG_OK;
    }
    if (*args->cursor == '@') {
        force_reg = 1;
        args->cursor++;
    }

    word = args->cursor;
    while (is_word_char(*args->cursor))
        args->cursor++;
    if (!force_reg && args->cursor > word && *args->cursor == '!' && args->cursor[1] != '=') {
        args->cursor++;
        while (is_word_char(*args->cursor))
            args->cursor++;
    }
    len = (size_t)(args->cursor - word);
    if (!len) {
        if (*start)
            return cmd_fail(args, start, "unexpected '%c'", *start);
        return cmd_fail(args, start, "expected an expression");
    }

    if (!force_reg) {
        size = mem_fn_size(dbg, word, len);
        next = args->cursor;
        while (*next == ' ' || *next == '\t')
            next++;
        if (size && *next == '(') {
            args->cursor = next + 1;
            status = parse_binary(dbg, args, 1, &addr);
            if (status != DBG_OK)
                return status;
            cmd_skip_ws(args);
            if (*args->cursor != ')')
                return cmd_fail(args, NULL, "expected ')'");
            args->cursor++;
            status = dbg_read_mem(dbg, EM_SPACE_VIRT, addr, &value, size, &done);
            if (status != DBG_OK || done != size)
                return cmd_fail(args, word, "cannot read memory at %llx", (unsigned long long)addr);
            *out = value;
            return DBG_OK;
        }
        if (parse_number(word, len, out))
            return DBG_OK;
    }

    reg = reg_find(word, len);
    if (reg) {
        regs = dbg_regs(dbg);
        if (!regs)
            return cmd_fail(args, word, "registers are not available while the target runs");
        if (!(regs->valid & EM_RB_BIT(reg->block)))
            return cmd_fail(args, word, "register '%s' is not available", reg->name);
        *out = reg_get(regs, reg);
        return DBG_OK;
    }
    if (!force_reg && dbg_sym_addr(dbg, word, len, out))
        return DBG_OK;
    return cmd_fail(args, word, "unknown symbol '%.*s'", (int)len, word);
}

static dbg_status parse_unary(dbg_ctx *dbg, cmd_args *args, uint64_t *out)
{
    char       op;
    uint64_t   value;
    dbg_status status;

    cmd_skip_ws(args);
    op = *args->cursor;
    if (op != '-' && op != '+' && op != '~' && op != '!')
        return parse_primary(dbg, args, out);
    args->cursor++;
    status = parse_unary(dbg, args, &value);
    if (status != DBG_OK)
        return status;
    switch (op) {
        case '-':
            *out = 0 - value;
            break;
        case '~':
            *out = ~value;
            break;
        case '!':
            *out = !value;
            break;
        default:
            *out = value;
            break;
    }
    return DBG_OK;
}

static dbg_status parse_binary(dbg_ctx *dbg, cmd_args *args, int min_prec, uint64_t *out)
{
    const char *op_at;
    uint64_t    left;
    uint64_t    right;
    binop       op;
    int         op_len;
    int         prec;
    dbg_status  status;

    status = parse_unary(dbg, args, &left);
    if (status != DBG_OK)
        return status;
    for (;;) {
        cmd_skip_ws(args);
        op = peek_binop(args->cursor, &op_len);
        prec = precedence(op);
        if (op == OP_NONE || prec < min_prec)
            break;
        op_at = args->cursor;
        args->cursor += op_len;
        status = parse_binary(dbg, args, prec + 1, &right);
        if (status != DBG_OK)
            return status;
        if ((op == OP_DIV || op == OP_MOD) && right == 0)
            return cmd_fail(args, op_at, "division by zero");
        left = apply(op, left, right);
    }
    *out = left;
    return DBG_OK;
}

dbg_status expr_eval(dbg_ctx *dbg, cmd_args *args, uint64_t *out)
{
    return parse_binary(dbg, args, 1, out);
}
