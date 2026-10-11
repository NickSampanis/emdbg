#include "cmd.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VALUE_TEXT          256
#define TYPE_TEXT           128
#define NAME_TEXT           128
#define MAX_TYPE_DEPTH      16
#define MAX_ELEMENTS_SHOWN  16
#define MAX_STRING_PREVIEW  64
#define MAX_CHILD_ELEMENTS  64
#define EXPR_TEXT           256
#define NONVOLATILE_GPRS    0xf0e8u

typedef enum value_kind {
    VALUE_MEMORY,
    VALUE_IMMEDIATE,
} value_kind;

typedef struct frame {
    sym_module     *module;
    const sym_func *func;
    uint64_t        pc;
    uint64_t        lookup;
    uint64_t        rva;
    uint64_t        sp;
    uint64_t        cfa;
    bool            have_cfa;
    bool            stopped;
    bool            exact;
    uint64_t        regs[UNWIND_GPRS];
    uint16_t        known;
    uint32_t        save_count;
    unwind_save     saves[UNWIND_MAX_SAVES];
} frame;

typedef struct value {
    const sym_module *module;
    uint32_t          type;
    uint8_t           kind;
    bool              address_of;
    uint16_t          bit_offset;
    uint16_t          bit_size;
    uint64_t          addr;
    uint64_t          bits;
} value;

typedef struct dx_parser {
    dbg_ctx  *dbg;
    cmd_args *args;
    frame     frame;
} dx_parser;

static const sym_type no_type;

static const sym_type *type_at(const sym_module *module, uint32_t index)
{
    if (!module || !module->types || index >= module->pub.type_count)
        return &no_type;
    return &module->types[index];
}

static uint32_t strip_typedefs(const sym_module *module, uint32_t index)
{
    int depth;

    for (depth = 0; depth < MAX_TYPE_DEPTH; depth++) {
        if (type_at(module, index)->kind != SYM_TYPE_TYPEDEF)
            break;
        index = type_at(module, index)->target;
    }
    return index;
}

static const sym_type *real_type(const sym_module *module, uint32_t index)
{
    return type_at(module, strip_typedefs(module, index));
}

static uint64_t type_size(const sym_module *module, uint32_t index, int depth)
{
    const sym_type *type;

    type = real_type(module, index);
    if (type->size || depth > MAX_TYPE_DEPTH)
        return type->size;
    if (type->kind == SYM_TYPE_ARRAY)
        return (uint64_t)type->count * type_size(module, type->target, depth + 1);
    return 0;
}

static uint64_t value_size(const value *val)
{
    if (val->address_of || !val->type)
        return 8;
    return type_size(val->module, val->type, 0);
}

static void type_name(const sym_module *module, uint32_t index, char *buf, size_t cap, int depth)
{
    const sym_type *type;
    char            inner[TYPE_TEXT];

    type = type_at(module, index);
    if (type->name && *type->name) {
        snprintf(buf, cap, "%s%s", type->flags & SYM_TYPE_CONST ? "const " : "", type->name);
        return;
    }
    if (depth > MAX_TYPE_DEPTH) {
        snprintf(buf, cap, "...");
        return;
    }
    switch (type->kind) {
        case SYM_TYPE_POINTER:
            type_name(module, type->target, inner, sizeof inner, depth + 1);
            snprintf(buf, cap, "%s *", inner);
            return;
        case SYM_TYPE_ARRAY:
            type_name(module, type->target, inner, sizeof inner, depth + 1);
            snprintf(buf, cap, "%s[%u]", inner, type->count);
            return;
        case SYM_TYPE_STRUCT:
            snprintf(buf, cap, "struct <anonymous>");
            return;
        case SYM_TYPE_UNION:
            snprintf(buf, cap, "union <anonymous>");
            return;
        case SYM_TYPE_ENUM:
            snprintf(buf, cap, "enum <anonymous>");
            return;
        case SYM_TYPE_FUNCTION:
            snprintf(buf, cap, "function");
            return;
        case SYM_TYPE_VOID:
            snprintf(buf, cap, "void");
            return;
        case SYM_TYPE_BOOL:
            snprintf(buf, cap, "bool");
            return;
        case SYM_TYPE_INT:
            snprintf(buf, cap, "int%u_t", type->size * 8);
            return;
        case SYM_TYPE_UINT:
            snprintf(buf, cap, "uint%u_t", type->size * 8);
            return;
        case SYM_TYPE_FLOAT:
            snprintf(buf, cap, type->size == 4 ? "float" : "double");
            return;
        default:
            snprintf(buf, cap, index ? "?" : "uint64_t");
            return;
    }
}

static void value_type_name(const value *val, char *buf, size_t cap)
{
    char inner[TYPE_TEXT];

    if (!val->address_of) {
        type_name(val->module, val->type, buf, cap, 0);
        return;
    }
    type_name(val->module, val->type, inner, sizeof inner, 0);
    snprintf(buf, cap, "%s *", inner);
}

static dbg_status read_virtual(dbg_ctx *dbg, uint64_t addr, void *buf, uint32_t len)
{
    uint32_t   done;
    dbg_status status;

    done = 0;
    status = dbg_read_mem(dbg, EM_SPACE_VIRT, addr, buf, len, &done);
    if (done == len)
        return DBG_OK;
    return status == DBG_OK ? DBG_E_FAULT : status;
}

static dbg_status value_load(dbg_ctx *dbg, const value *val, uint64_t *out)
{
    uint8_t    bytes[8];
    uint64_t   size;
    uint64_t   raw;
    uint32_t   index;
    dbg_status status;

    raw = 0;
    if (val->kind == VALUE_IMMEDIATE) {
        *out = val->bits;
        return DBG_OK;
    }
    size = value_size(val);
    if (size == 0 || size > 8)
        return DBG_E_BADARG;
    status = read_virtual(dbg, val->addr, bytes, (uint32_t)size);
    if (status != DBG_OK)
        return status;
    for (index = 0; index < size; index++)
        raw |= (uint64_t)bytes[index] << (index * 8);
    if (val->bit_size && val->bit_size < 64)
        raw = (raw >> val->bit_offset) & ((1ull << val->bit_size) - 1);
    *out = raw;
    return DBG_OK;
}

static int64_t sign_extend(uint64_t raw, uint32_t bits)
{
    if (bits == 0 || bits >= 64)
        return (int64_t)raw;
    if (raw & (1ull << (bits - 1)))
        return (int64_t)(raw | ~((1ull << bits) - 1));
    return (int64_t)raw;
}

static bool char_like(const sym_module *module, uint32_t index)
{
    const sym_type *type;

    type = real_type(module, index);
    return (type->flags & SYM_TYPE_CHAR) && (type->size == 1 || type->size == 2);
}

static void append_string(dbg_ctx *dbg, const sym_module *module, uint32_t char_type,
                          uint64_t addr, uint32_t limit, char *buf, size_t cap)
{
    uint8_t  bytes[MAX_STRING_PREVIEW * 2];
    char     text[MAX_STRING_PREVIEW + 1];
    uint32_t width;
    uint32_t count;
    uint32_t index;
    uint32_t ch;
    size_t   len;

    width = real_type(module, char_type)->size;
    count = limit < MAX_STRING_PREVIEW ? limit : MAX_STRING_PREVIEW;
    if (!addr || !count || read_virtual(dbg, addr, bytes, count * width) != DBG_OK)
        return;
    for (index = 0; index < count; index++) {
        ch = width == 2 ? (uint32_t)(bytes[index * 2] | bytes[index * 2 + 1] << 8) : bytes[index];
        if (!ch)
            break;
        text[index] = ch < 0x80 && isprint((int)ch) ? (char)ch : '.';
    }
    text[index] = '\0';
    len = strlen(buf);
    snprintf(buf + len, cap - len, " \"%s%s\"", width == 2 ? "L" : "", text);
}

static void format_number(const sym_type *type, uint64_t raw, uint32_t bits, char *buf,
                          size_t cap)
{
    int64_t signed_value;

    if (type->kind == SYM_TYPE_INT) {
        signed_value = sign_extend(raw, bits);
        if (signed_value >= 0 && signed_value < 10)
            snprintf(buf, cap, "%" PRId64, signed_value);
        else
            snprintf(buf, cap, "%" PRId64 " (0x%" PRIx64 ")", signed_value, raw);
    } else if (raw < 10) {
        snprintf(buf, cap, "%" PRIu64, raw);
    } else {
        snprintf(buf, cap, "%" PRIu64 " (0x%" PRIx64 ")", raw, raw);
    }
}

static void format_enum(const sym_module *module, const sym_type *type, uint64_t raw, char *buf,
                        size_t cap)
{
    const sym_enumerator *enumerator;
    int64_t               number;
    uint32_t              index;

    number = sign_extend(raw, type->size * 8);
    for (index = 0; index < type->member_count; index++) {
        enumerator = &module->enumerators[type->first_member + index];
        if (enumerator->value == number) {
            snprintf(buf, cap, "%s (%" PRId64 ")", enumerator->name, number);
            return;
        }
    }
    snprintf(buf, cap, "%" PRId64, number);
}

static void format_pointer(dbg_ctx *dbg, const sym_module *module, uint32_t target,
                           uint64_t pointer, char *buf, size_t cap)
{
    char   symbol[160];
    size_t len;

    snprintf(buf, cap, "0x%016" PRIx64, pointer);
    if (dbg_sym_format(dbg, pointer, symbol, sizeof symbol)) {
        len = strlen(buf);
        snprintf(buf + len, cap - len, " %s", symbol);
    }
    if (char_like(module, target))
        append_string(dbg, module, target, pointer, MAX_STRING_PREVIEW, buf, cap);
}

static void format_short(dbg_ctx *dbg, const value *val, char *buf, size_t cap)
{
    const sym_type *type;
    uint64_t        raw;
    float           single;
    double          wide;
    uint32_t        bits;

    if (val->address_of) {
        format_pointer(dbg, val->module, val->type, val->bits, buf, cap);
        return;
    }
    type = real_type(val->module, val->type);
    if (type->kind == SYM_TYPE_STRUCT || type->kind == SYM_TYPE_UNION) {
        snprintf(buf, cap, "{...}");
        return;
    }
    if (type->kind == SYM_TYPE_ARRAY) {
        snprintf(buf, cap, "[%u]", type->count);
        if (val->kind == VALUE_MEMORY && char_like(val->module, type->target))
            append_string(dbg, val->module, type->target, val->addr, type->count, buf, cap);
        return;
    }
    if (type->kind == SYM_TYPE_FUNCTION || type->kind == SYM_TYPE_VOID) {
        snprintf(buf, cap, val->kind == VALUE_MEMORY ? "at 0x%016" PRIx64 : "-", val->addr);
        return;
    }
    if (value_load(dbg, val, &raw) != DBG_OK) {
        if (val->kind == VALUE_MEMORY)
            snprintf(buf, cap, "<memory not accessible at 0x%016" PRIx64 ">", val->addr);
        else
            snprintf(buf, cap, "<unavailable>");
        return;
    }
    bits = val->bit_size ? val->bit_size : (uint32_t)value_size(val) * 8;
    switch (type->kind) {
        case SYM_TYPE_BOOL:
            snprintf(buf, cap, raw ? "true" : "false");
            return;
        case SYM_TYPE_FLOAT:
            if (type->size == 4) {
                memcpy(&single, &raw, sizeof single);
                snprintf(buf, cap, "%g", (double)single);
            } else {
                memcpy(&wide, &raw, sizeof wide);
                snprintf(buf, cap, "%g", wide);
            }
            return;
        case SYM_TYPE_ENUM:
            format_enum(val->module, type, raw, buf, cap);
            return;
        case SYM_TYPE_POINTER:
            format_pointer(dbg, val->module, type->target, raw, buf, cap);
            return;
        case SYM_TYPE_INT:
        case SYM_TYPE_UINT:
            format_number(type, raw, bits, buf, cap);
            if ((type->flags & SYM_TYPE_CHAR) && raw >= 0x20 && raw < 0x7f) {
                bits = (uint32_t)strlen(buf);
                snprintf(buf + bits, cap - bits, " '%c'", (char)raw);
            }
            return;
        default:
            snprintf(buf, cap, "0x%016" PRIx64, raw);
            return;
    }
}

static bool frame_gpr(const frame *frame_info, uint8_t index, uint64_t *out)
{
    if (index >= UNWIND_GPRS || !(frame_info->known & (1u << index)))
        return false;
    *out = frame_info->regs[index];
    return true;
}

static bool frame_reg(dbg_ctx *dbg, const frame *frame_info, const reg_def *reg, uint64_t *out)
{
    uint8_t shift;
    uint8_t size;
    int     index;

    index = unwind_gpr(reg->name, &shift, &size);
    if (index < 0) {
        if (!frame_info->exact)
            return false;
        *out = reg_get(&dbg->regs, reg);
        return true;
    }
    if (!frame_gpr(frame_info, (uint8_t)index, out))
        return false;
    *out >>= shift;
    if (size < 8)
        *out &= (1ull << (size * 8)) - 1;
    return true;
}

static void target_gprs(const dbg_ctx *dbg, uint64_t *regs, uint16_t *known)
{
    const em_x86_core *core;

    core = &dbg->regs.core;
    regs[0] = core->rax;
    regs[1] = core->rcx;
    regs[2] = core->rdx;
    regs[3] = core->rbx;
    regs[4] = dbg_stack_pointer(dbg);
    regs[5] = core->rbp;
    regs[6] = core->rsi;
    regs[7] = core->rdi;
    regs[8] = core->r8;
    regs[9] = core->r9;
    regs[10] = core->r10;
    regs[11] = core->r11;
    regs[12] = core->r12;
    regs[13] = core->r13;
    regs[14] = core->r14;
    regs[15] = core->r15;
    *known = 0xffff;
}

static const sym_cfa *symbol_cfa_rule(const frame *frame_info)
{
    const sym_cfa *rule;
    const sym_cfa *best;
    uint32_t       index;

    best = NULL;
    if (!frame_info->func)
        return NULL;
    for (index = 0; index < frame_info->func->cfa_count; index++) {
        rule = &frame_info->module->cfas[frame_info->func->first_cfa + index];
        if (rule->start > frame_info->rva || !rule->reg)
            continue;
        if (!best || rule->start >= best->start)
            best = rule;
    }
    return best;
}

static void frame_setup(dbg_ctx *dbg, frame *out, uint64_t pc, const uint64_t *regs,
                        uint16_t known, bool caller)
{
    const sym_cfa *rule;
    unwind_result  result;
    uint64_t       base;

    memset(out, 0, sizeof *out);
    out->stopped = true;
    out->exact = !caller;
    out->pc = pc;
    out->lookup = caller ? pc - 1 : pc;
    memcpy(out->regs, regs, sizeof out->regs);
    out->known = known;
    out->sp = regs[UNWIND_GPR_SP];
    out->module = sym_module_at(dbg, out->lookup);
    if (out->module) {
        out->rva = out->lookup - out->module->pub.base;
        out->func = sym_func_in(out->module, out->lookup);
    }
    rule = symbol_cfa_rule(out);
    if (rule && frame_reg(dbg, out, rule->reg, &base)) {
        out->cfa = base + (uint64_t)rule->offset;
        out->have_cfa = true;
        return;
    }
    if (!unwind_rule(dbg, out->pc, out->lookup, &result) ||
        !frame_gpr(out, result.base, &base))
        return;
    out->cfa = base + (uint64_t)result.offset;
    out->have_cfa = true;
    out->save_count = result.save_count;
    memcpy(out->saves, result.saves, sizeof out->saves);
}

static void frame_top(dbg_ctx *dbg, frame *out)
{
    uint64_t regs[UNWIND_GPRS];
    uint16_t known;

    target_gprs(dbg, regs, &known);
    frame_setup(dbg, out, dbg_pc(dbg), regs, known, false);
}

typedef struct unwinder {
    uint64_t pc;
    uint64_t regs[UNWIND_GPRS];
    uint16_t known;
    uint32_t number;
    uint32_t pointer_size;
    bool     done;
} unwinder;

static void unwind_start(dbg_ctx *dbg, unwinder *walk)
{
    walk->pc = dbg_pc(dbg);
    target_gprs(dbg, walk->regs, &walk->known);
    walk->number = 0;
    walk->pointer_size = dbg->mode == DBG_MODE_LONG64 ? 8u : 4u;
    walk->done = false;
}

static void caller_registers(dbg_ctx *dbg, const frame *callee, unwinder *walk)
{
    const unwind_save *save;
    uint64_t           base;
    uint64_t           value;
    uint32_t           index;

    memcpy(walk->regs, callee->regs, sizeof walk->regs);
    walk->known = callee->known & NONVOLATILE_GPRS;
    walk->regs[UNWIND_GPR_SP] = callee->cfa;
    walk->known |= 1u << UNWIND_GPR_SP;
    for (index = 0; index < callee->save_count; index++) {
        save = &callee->saves[index];
        if (save->reg == UNWIND_GPR_SP || save->reg >= UNWIND_GPRS)
            continue;
        value = 0;
        if (frame_gpr(callee, save->base, &base) &&
            read_virtual(dbg, base + (uint64_t)save->offset, &value, walk->pointer_size) ==
                DBG_OK) {
            walk->regs[save->reg] = value;
            walk->known |= 1u << save->reg;
        } else {
            walk->known &= ~(1u << save->reg);
        }
    }
}

static bool unwind_step(dbg_ctx *dbg, unwinder *walk, frame *frame_info, dbg_frame *stack_frame)
{
    uint64_t return_addr;

    if (walk->done)
        return false;
    frame_setup(dbg, frame_info, walk->pc, walk->regs, walk->known, walk->number > 0);
    memset(stack_frame, 0, sizeof *stack_frame);
    stack_frame->number = walk->number;
    stack_frame->pc = walk->pc;
    stack_frame->sp = frame_info->sp;
    stack_frame->cfa = frame_info->cfa;
    stack_frame->have_cfa = frame_info->have_cfa;
    return_addr = 0;
    if (frame_info->have_cfa &&
        read_virtual(dbg, frame_info->cfa - walk->pointer_size, &return_addr,
                     walk->pointer_size) == DBG_OK && return_addr) {
        stack_frame->return_addr = return_addr;
        stack_frame->have_return = true;
    }
    if (!stack_frame->have_return || frame_info->cfa <= frame_info->sp) {
        walk->done = true;
    } else {
        caller_registers(dbg, frame_info, walk);
        walk->pc = return_addr;
    }
    walk->number++;
    return true;
}

static bool frame_number(dbg_ctx *dbg, uint32_t number, frame *frame_info,
                         dbg_frame *stack_frame)
{
    unwinder walk;

    unwind_start(dbg, &walk);
    while (unwind_step(dbg, &walk, frame_info, stack_frame))
        if (stack_frame->number == number)
            return true;
    return false;
}

static dbg_status frame_at_pc(dbg_ctx *dbg, frame *out)
{
    dbg_frame stack_frame;

    memset(out, 0, sizeof *out);
    if (dbg->state != DBG_STATE_STOPPED || !dbg_regs(dbg))
        return DBG_OK;
    if (dbg->frame_index && frame_number(dbg, dbg->frame_index, out, &stack_frame))
        return DBG_OK;
    dbg->frame_index = 0;
    frame_top(dbg, out);
    return DBG_OK;
}

bool sym_frame_cfa(dbg_ctx *dbg, uint64_t *cfa)
{
    frame frame_info;

    if (dbg->state != DBG_STATE_STOPPED || !dbg_regs(dbg))
        return false;
    frame_top(dbg, &frame_info);
    if (!frame_info.have_cfa)
        return false;
    *cfa = frame_info.cfa;
    return true;
}

dbg_status dbg_set_frame(dbg_ctx *dbg, uint32_t number)
{
    frame     frame_info;
    dbg_frame stack_frame;

    if (dbg->state != DBG_STATE_STOPPED || !dbg_regs(dbg))
        return DBG_E_RUNNING;
    if (!frame_number(dbg, number, &frame_info, &stack_frame))
        return DBG_E_BADARG;
    dbg->frame_index = number;
    return DBG_OK;
}

uint32_t dbg_get_frame(const dbg_ctx *dbg)
{
    return dbg->frame_index;
}

dbg_status dbg_frame_info(dbg_ctx *dbg, dbg_frame *out)
{
    frame frame_info;

    if (dbg->state != DBG_STATE_STOPPED || !dbg_regs(dbg))
        return DBG_E_RUNNING;
    if (frame_number(dbg, dbg->frame_index, &frame_info, out))
        return DBG_OK;
    dbg->frame_index = 0;
    return frame_number(dbg, 0, &frame_info, out) ? DBG_OK : DBG_E_BADARG;
}

static const sym_location *location_at(const sym_module *module, const sym_var *var,
                                       uint64_t rva)
{
    const sym_location *location;
    const sym_location *fallback;
    uint32_t            index;

    fallback = NULL;
    for (index = 0; index < var->loc_count; index++) {
        location = &module->locations[var->first_loc + index];
        if (!location->start && !location->end) {
            if (!fallback)
                fallback = location;
        } else if (rva >= location->start && rva < location->end) {
            return location;
        }
    }
    return fallback;
}

static bool in_scope(const sym_var *var, uint64_t rva)
{
    return (!var->scope_start && !var->scope_end) ||
           (rva >= var->scope_start && rva < var->scope_end);
}

static const char *var_value(dbg_ctx *dbg, const frame *frame_info, const sym_module *module,
                             const sym_var *var, value *out)
{
    const sym_location *location;
    uint64_t            size;

    memset(out, 0, sizeof *out);
    out->module = module;
    out->type = var->type;
    location = location_at(module, var, frame_info->rva);
    if (!location || location->kind == SYM_LOC_NONE)
        return "not available at this address";
    switch (location->kind) {
        case SYM_LOC_ABSOLUTE:
            out->kind = VALUE_MEMORY;
            out->addr = module->pub.base + (uint64_t)location->offset;
            return NULL;
        case SYM_LOC_CFA:
            if (!frame_info->have_cfa)
                return "the frame of this function is unknown";
            out->kind = VALUE_MEMORY;
            out->addr = frame_info->cfa + (uint64_t)location->offset;
            return NULL;
        case SYM_LOC_REG_RELATIVE:
            if (!frame_info->stopped)
                return "registers are not available while the target runs";
            if (!frame_reg(dbg, frame_info, location->reg, &out->addr))
                return "its register is unknown in a caller frame";
            out->kind = VALUE_MEMORY;
            out->addr += (uint64_t)location->offset;
            return NULL;
        case SYM_LOC_REGISTER:
            if (!frame_info->stopped)
                return "registers are not available while the target runs";
            if (!frame_reg(dbg, frame_info, location->reg, &out->bits))
                return "in a register, unknown in a caller frame";
            out->kind = VALUE_IMMEDIATE;
            size = value_size(out);
            if (size && size < 8)
                out->bits &= (1ull << (size * 8)) - 1;
            return NULL;
        case SYM_LOC_VALUE:
            out->kind = VALUE_IMMEDIATE;
            out->bits = (uint64_t)location->offset;
            return NULL;
    }
    return "not available at this address";
}

static bool name_matches(const char *name, const char *text, size_t len)
{
    return strlen(name) == len && !memcmp(name, text, len);
}

static const sym_var *find_global(const sym_module *module, const char *name, size_t len)
{
    const sym_var *var;
    uint32_t       low;
    uint32_t       high;
    uint32_t       middle;
    int            order;

    low = 0;
    high = module->globals_by_name ? module->pub.global_count : 0;
    while (low < high) {
        middle = low + (high - low) / 2;
        var = module->globals_by_name[middle];
        order = strncmp(var->name, name, len);
        if (!order)
            order = var->name[len] ? 1 : 0;
        if (!order)
            return var;
        if (order < 0)
            low = middle + 1;
        else
            high = middle;
    }
    return NULL;
}

static bool module_matches(const sym_module *module, const char *name, size_t len)
{
    size_t index;

    if (strlen(module->name) != len)
        return false;
    for (index = 0; index < len; index++)
        if (tolower((unsigned char)module->name[index]) != tolower((unsigned char)name[index]))
            return false;
    return true;
}

static dbg_status lookup(dx_parser *parser, const char *name, size_t len, value *out)
{
    const sym_module *module;
    const sym_var    *var;
    const reg_def    *reg;
    const char       *bang;
    const char       *problem;
    uint32_t          index;
    int               module_index;

    var = NULL;
    module = NULL;
    bang = memchr(name, '!', len);
    if (!bang && parser->frame.func) {
        for (index = 0; index < parser->frame.func->var_count && !var; index++) {
            var = &parser->frame.module->vars[parser->frame.func->first_var + index];
            if (!in_scope(var, parser->frame.rva) || !name_matches(var->name, name, len))
                var = NULL;
        }
        module = parser->frame.module;
    }
    if (!var && !bang && parser->frame.module) {
        module = parser->frame.module;
        var = find_global(module, name, len);
    }
    for (module_index = 0; !var && module_index < parser->dbg->module_count; module_index++) {
        module = &parser->dbg->modules[module_index];
        if (bang && !module_matches(module, name, (size_t)(bang - name)))
            continue;
        var = bang ? find_global(module, bang + 1, (size_t)(name + len - bang - 1))
                   : find_global(module, name, len);
    }
    if (var) {
        problem = var_value(parser->dbg, &parser->frame, module, var, out);
        if (problem)
            return cmd_fail(parser->args, name, "'%.*s': %s", (int)len, name, problem);
        return DBG_OK;
    }
    reg = bang ? NULL : reg_find(name, len);
    if (reg && parser->frame.stopped) {
        memset(out, 0, sizeof *out);
        out->kind = VALUE_IMMEDIATE;
        out->bits = reg_get(&parser->dbg->regs, reg);
        return DBG_OK;
    }
    return cmd_fail(parser->args, name, "unknown variable '%.*s'", (int)len, name);
}

static bool is_ident_start(char ch)
{
    return isalpha((unsigned char)ch) || ch == '_';
}

static bool is_ident_char(char ch)
{
    return isalnum((unsigned char)ch) || ch == '_';
}

static dbg_status parse_index(dx_parser *parser, uint64_t *out)
{
    const char *start;
    char       *end;

    cmd_skip_ws(parser->args);
    start = parser->args->cursor;
    if (!isdigit((unsigned char)*start))
        return cmd_fail(parser->args, NULL, "expected an index");
    *out = strtoull(start, &end, start[0] == '0' && (start[1] == 'x' || start[1] == 'X') ? 16
                                                                                      : 10);
    parser->args->cursor = end;
    cmd_skip_ws(parser->args);
    if (*parser->args->cursor != ']')
        return cmd_fail(parser->args, NULL, "expected ']'");
    parser->args->cursor++;
    return DBG_OK;
}

static dbg_status deref(dx_parser *parser, const char *at, const value *val, value *out)
{
    const sym_type *type;
    uint64_t        pointer;

    memset(out, 0, sizeof *out);
    out->module = val->module;
    out->kind = VALUE_MEMORY;
    if (val->address_of) {
        out->type = val->type;
        out->addr = val->bits;
        return DBG_OK;
    }
    type = real_type(val->module, val->type);
    if (type->kind != SYM_TYPE_POINTER)
        return cmd_fail(parser->args, at, "not a pointer");
    if (value_load(parser->dbg, val, &pointer) != DBG_OK)
        return cmd_fail(parser->args, at, "cannot read the pointer");
    if (!pointer)
        return cmd_fail(parser->args, at, "NULL pointer");
    out->type = type->target;
    out->addr = pointer;
    return DBG_OK;
}

static dbg_status member(dx_parser *parser, const char *at, const value *val, const char *name,
                         size_t len, value *out)
{
    const sym_type   *type;
    const sym_member *field;
    uint32_t          index;

    type = real_type(val->module, val->type);
    if (val->address_of || type->kind == SYM_TYPE_POINTER)
        return cmd_fail(parser->args, at, "this is a pointer; use ->");
    if (type->kind != SYM_TYPE_STRUCT && type->kind != SYM_TYPE_UNION)
        return cmd_fail(parser->args, at, "not a struct or union");
    if (type->flags & SYM_TYPE_FORWARD)
        return cmd_fail(parser->args, at, "incomplete type (only declared)");
    if (val->kind != VALUE_MEMORY)
        return cmd_fail(parser->args, at, "the value is in a register; its members are not");
    for (index = 0; index < type->member_count; index++) {
        field = &val->module->members[type->first_member + index];
        if (!name_matches(field->name, name, len))
            continue;
        memset(out, 0, sizeof *out);
        out->module = val->module;
        out->kind = VALUE_MEMORY;
        out->type = field->type;
        out->addr = val->addr + field->offset;
        out->bit_offset = field->bit_offset;
        out->bit_size = field->bit_size;
        return DBG_OK;
    }
    return cmd_fail(parser->args, name, "no member '%.*s'", (int)len, name);
}

static dbg_status element(dx_parser *parser, const char *at, const value *val, uint64_t index,
                          value *out)
{
    const sym_type *type;
    uint64_t        base;
    uint64_t        size;
    uint32_t        target;

    type = real_type(val->module, val->type);
    if (val->address_of) {
        target = val->type;
        base = val->bits;
    } else if (type->kind == SYM_TYPE_ARRAY && val->kind == VALUE_MEMORY) {
        target = type->target;
        base = val->addr;
    } else if (type->kind == SYM_TYPE_POINTER) {
        target = type->target;
        if (value_load(parser->dbg, val, &base) != DBG_OK)
            return cmd_fail(parser->args, at, "cannot read the pointer");
    } else {
        return cmd_fail(parser->args, at, "not an array or pointer");
    }
    size = type_size(val->module, target, 0);
    if (!size)
        return cmd_fail(parser->args, at, "the element size is unknown");
    memset(out, 0, sizeof *out);
    out->module = val->module;
    out->kind = VALUE_MEMORY;
    out->type = target;
    out->addr = base + index * size;
    return DBG_OK;
}

static dbg_status parse_unary(dx_parser *parser, value *out);

static dbg_status parse_primary(dx_parser *parser, value *out)
{
    const char *start;
    dbg_status  status;

    cmd_skip_ws(parser->args);
    start = parser->args->cursor;
    if (*start == '(') {
        parser->args->cursor++;
        status = parse_unary(parser, out);
        if (status != DBG_OK)
            return status;
        cmd_skip_ws(parser->args);
        if (*parser->args->cursor != ')')
            return cmd_fail(parser->args, NULL, "expected ')'");
        parser->args->cursor++;
        return DBG_OK;
    }
    if (!is_ident_start(*start))
        return cmd_fail(parser->args, NULL, "expected a variable name");
    while (is_ident_char(*parser->args->cursor))
        parser->args->cursor++;
    if (*parser->args->cursor == '!' && is_ident_start(parser->args->cursor[1])) {
        parser->args->cursor++;
        while (is_ident_char(*parser->args->cursor))
            parser->args->cursor++;
    }
    return lookup(parser, start, (size_t)(parser->args->cursor - start), out);
}

static dbg_status parse_postfix(dx_parser *parser, value *out)
{
    value       inner;
    const char *at;
    const char *name;
    uint64_t    index;
    bool        arrow;
    dbg_status  status;

    status = parse_primary(parser, out);
    while (status == DBG_OK) {
        cmd_skip_ws(parser->args);
        at = parser->args->cursor;
        arrow = at[0] == '-' && at[1] == '>';
        if (*at == '[') {
            parser->args->cursor++;
            status = parse_index(parser, &index);
            if (status == DBG_OK)
                status = element(parser, at, out, index, &inner);
        } else if (*at == '.' || arrow) {
            parser->args->cursor += arrow ? 2 : 1;
            cmd_skip_ws(parser->args);
            name = parser->args->cursor;
            while (is_ident_char(*parser->args->cursor))
                parser->args->cursor++;
            if (parser->args->cursor == name)
                return cmd_fail(parser->args, NULL, "expected a member name");
            status = arrow ? deref(parser, at, out, &inner) : DBG_OK;
            if (status == DBG_OK && arrow)
                *out = inner;
            if (status == DBG_OK)
                status = member(parser, at, out, name, (size_t)(parser->args->cursor - name),
                                &inner);
        } else {
            break;
        }
        if (status == DBG_OK)
            *out = inner;
    }
    return status;
}

static dbg_status parse_unary(dx_parser *parser, value *out)
{
    value       inner;
    const char *at;
    dbg_status  status;

    cmd_skip_ws(parser->args);
    at = parser->args->cursor;
    if (*at != '*' && *at != '&')
        return parse_postfix(parser, out);
    parser->args->cursor++;
    status = parse_unary(parser, &inner);
    if (status != DBG_OK)
        return status;
    if (*at == '*')
        return deref(parser, at, &inner, out);
    if (inner.kind != VALUE_MEMORY || inner.bit_size || inner.address_of)
        return cmd_fail(parser->args, at, "has no address");
    memset(out, 0, sizeof *out);
    out->module = inner.module;
    out->type = inner.type;
    out->kind = VALUE_IMMEDIATE;
    out->address_of = true;
    out->bits = inner.addr;
    return DBG_OK;
}

static dbg_status evaluate(dbg_ctx *dbg, cmd_args *args, value *out)
{
    dx_parser  parser;
    dbg_status status;

    parser.dbg = dbg;
    parser.args = args;
    status = frame_at_pc(dbg, &parser.frame);
    if (status != DBG_OK)
        return status;
    status = parse_unary(&parser, out);
    if (status == DBG_OK && !cmd_at_end(args))
        status = cmd_fail(args, NULL, "unexpected '%s'", args->cursor);
    return status;
}

static void member_value(const value *val, const sym_member *field, value *out)
{
    memset(out, 0, sizeof *out);
    out->module = val->module;
    out->kind = VALUE_MEMORY;
    out->type = field->type;
    out->addr = val->addr + field->offset;
    out->bit_offset = field->bit_offset;
    out->bit_size = field->bit_size;
}

static void element_value(const value *val, uint32_t target, uint64_t size, uint32_t index,
                          value *out)
{
    memset(out, 0, sizeof *out);
    out->module = val->module;
    out->kind = VALUE_MEMORY;
    out->type = target;
    out->addr = val->addr + index * size;
}

static dbg_status pointee(dbg_ctx *dbg, const value *val, value *out)
{
    const sym_type *type;
    uint64_t        pointer;

    memset(out, 0, sizeof *out);
    out->module = val->module;
    out->kind = VALUE_MEMORY;
    if (val->address_of) {
        out->type = val->type;
        out->addr = val->bits;
        return DBG_OK;
    }
    type = real_type(val->module, val->type);
    if (type->kind != SYM_TYPE_POINTER)
        return DBG_E_BADARG;
    if (value_load(dbg, val, &pointer) != DBG_OK)
        return DBG_E_FAULT;
    if (!pointer)
        return DBG_E_FAULT;
    out->type = type->target;
    out->addr = pointer;
    return DBG_OK;
}

static bool value_expandable(const value *val)
{
    const sym_type *type;
    const sym_type *target;

    type = real_type(val->module, val->type);
    if (val->address_of)
        return type->kind != SYM_TYPE_VOID && type->kind != SYM_TYPE_FUNCTION;
    switch (type->kind) {
        case SYM_TYPE_STRUCT:
        case SYM_TYPE_UNION:
            return val->kind == VALUE_MEMORY && !(type->flags & SYM_TYPE_FORWARD) &&
                   type->member_count;
        case SYM_TYPE_ARRAY:
            return val->kind == VALUE_MEMORY && type->count;
        case SYM_TYPE_POINTER:
            target = real_type(val->module, type->target);
            return target->kind != SYM_TYPE_VOID && target->kind != SYM_TYPE_FUNCTION &&
                   target->kind != SYM_TYPE_NONE;
        default:
            return false;
    }
}

static void print_members(dbg_ctx *dbg, const value *val, const sym_type *type)
{
    const sym_member *field;
    value             child;
    char              text[VALUE_TEXT];
    char              type_text[TYPE_TEXT];
    uint32_t          index;

    for (index = 0; index < type->member_count; index++) {
        field = &val->module->members[type->first_member + index];
        member_value(val, field, &child);
        format_short(dbg, &child, text, sizeof text);
        type_name(val->module, field->type, type_text, sizeof type_text, 0);
        dbg_out(dbg, DBG_OUT_NORMAL, "    %-24s : %-28s %s\n", field->name, text, type_text);
    }
}

static void print_elements(dbg_ctx *dbg, const value *val, const sym_type *type)
{
    value    child;
    char     text[VALUE_TEXT];
    uint64_t size;
    uint32_t index;

    size = type_size(val->module, type->target, 0);
    for (index = 0; index < type->count && index < MAX_ELEMENTS_SHOWN && size; index++) {
        element_value(val, type->target, size, index, &child);
        format_short(dbg, &child, text, sizeof text);
        dbg_out(dbg, DBG_OUT_NORMAL, "    [%u] : %s\n", index, text);
    }
    if (type->count > MAX_ELEMENTS_SHOWN)
        dbg_out(dbg, DBG_OUT_NORMAL, "    ... %u more\n", type->count - MAX_ELEMENTS_SHOWN);
}

static void print_expanded(dbg_ctx *dbg, const value *val)
{
    const sym_type *type;
    value           target;

    type = real_type(val->module, val->type);
    if (val->address_of || type->kind == SYM_TYPE_POINTER) {
        if (pointee(dbg, val, &target) != DBG_OK)
            return;
        type = real_type(target.module, target.type);
        if (type->kind == SYM_TYPE_STRUCT || type->kind == SYM_TYPE_UNION)
            print_members(dbg, &target, type);
        return;
    }
    if ((type->kind == SYM_TYPE_STRUCT || type->kind == SYM_TYPE_UNION) &&
        val->kind == VALUE_MEMORY)
        print_members(dbg, val, type);
    else if (type->kind == SYM_TYPE_ARRAY && val->kind == VALUE_MEMORY)
        print_elements(dbg, val, type);
}

dbg_status value_dx(dbg_ctx *dbg, cmd_args *args)
{
    value      val;
    char       text[VALUE_TEXT];
    char       type_text[TYPE_TEXT];
    dbg_status status;

    if (cmd_at_end(args))
        return cmd_fail(args, NULL, "expected an expression, like ctx->Field");
    status = evaluate(dbg, args, &val);
    if (status != DBG_OK)
        return status;
    value_type_name(&val, type_text, sizeof type_text);
    format_short(dbg, &val, text, sizeof text);
    if (val.kind == VALUE_MEMORY)
        dbg_out(dbg, DBG_OUT_NORMAL, "(%s) %s  @ 0x%016" PRIx64 "\n", type_text, text, val.addr);
    else
        dbg_out(dbg, DBG_OUT_NORMAL, "(%s) %s\n", type_text, text);
    print_expanded(dbg, &val);
    return DBG_OK;
}

static dbg_status frame_vars(dbg_ctx *dbg, const frame *frame_info, bool params_only,
                             dbg_local_fn fn, void *user)
{
    const sym_var *var;
    value          val;
    dbg_local      local;
    const char    *problem;
    char           text[VALUE_TEXT];
    char           type_text[TYPE_TEXT];
    uint32_t       index;

    if (!frame_info->func)
        return DBG_E_BADARG;
    for (index = 0; index < frame_info->func->var_count; index++) {
        var = &frame_info->module->vars[frame_info->func->first_var + index];
        if (!in_scope(var, frame_info->rva))
            continue;
        if (params_only && !(var->flags & SYM_VAR_PARAM))
            continue;
        problem = var_value(dbg, frame_info, frame_info->module, var, &val);
        if (problem)
            snprintf(text, sizeof text, "<%s>", problem);
        else
            format_short(dbg, &val, text, sizeof text);
        type_name(frame_info->module, var->type, type_text, sizeof type_text, 0);
        local.expandable = !problem && value_expandable(&val);
        local.is_param = (var->flags & SYM_VAR_PARAM) != 0;
        local.name = var->name;
        local.type = type_text;
        local.value = text;
        fn(user, &local);
    }
    return DBG_OK;
}

dbg_status dbg_locals(dbg_ctx *dbg, dbg_local_fn fn, void *user)
{
    frame      frame_info;
    dbg_status status;

    status = frame_at_pc(dbg, &frame_info);
    if (status != DBG_OK)
        return status;
    if (!frame_info.stopped)
        return DBG_E_RUNNING;
    return frame_vars(dbg, &frame_info, false, fn, user);
}

dbg_status dbg_frame_params(dbg_ctx *dbg, const dbg_frame *stack_frame, dbg_local_fn fn,
                            void *user)
{
    frame     frame_info;
    dbg_frame found;

    if (dbg->state != DBG_STATE_STOPPED || !dbg_regs(dbg))
        return DBG_E_RUNNING;
    if (!frame_number(dbg, stack_frame->number, &frame_info, &found))
        return DBG_E_BADARG;
    return frame_vars(dbg, &frame_info, true, fn, user);
}

dbg_status dbg_stack_walk(dbg_ctx *dbg, uint32_t max_frames, dbg_frame_fn fn, void *user)
{
    unwinder  walk;
    frame     frame_info;
    dbg_frame stack_frame;

    if (dbg->state != DBG_STATE_STOPPED || !dbg_regs(dbg))
        return DBG_E_RUNNING;
    unwind_start(dbg, &walk);
    while (walk.number < max_frames && unwind_step(dbg, &walk, &frame_info, &stack_frame))
        if (!fn(user, &stack_frame))
            break;
    return DBG_OK;
}

static void print_local(void *user, const dbg_local *local)
{
    dbg_out((dbg_ctx *)user, DBG_OUT_NORMAL, "  %-5s %-24s %-20s = %s\n",
            local->is_param ? "param" : "local", local->type, local->name, local->value);
}

dbg_status value_dv(dbg_ctx *dbg)
{
    char       name[NAME_TEXT];
    dbg_status status;

    status = dbg_locals(dbg, print_local, dbg);
    if (status == DBG_E_BADARG) {
        if (!dbg_sym_format(dbg, dbg_pc(dbg), name, sizeof name))
            snprintf(name, sizeof name, "%016" PRIx64, dbg_pc(dbg));
        dbg_out(dbg, DBG_OUT_NORMAL, "no function symbols at %s\n", name);
        return DBG_OK;
    }
    return status;
}

static dbg_status evaluate_text(dbg_ctx *dbg, const char *expr, value *val, char *error,
                                size_t error_cap)
{
    cmd_args   args;
    dbg_status status;

    args.line = expr;
    args.cursor = expr;
    args.err_at = NULL;
    args.err[0] = '\0';
    status = evaluate(dbg, &args, val);
    if (status != DBG_OK)
        snprintf(error, error_cap, "%s", args.err[0] ? args.err : dbg_status_str(status));
    return status;
}

dbg_status dbg_eval(dbg_ctx *dbg, const char *expr, dbg_eval_result *out)
{
    value      val;
    dbg_status status;

    memset(out, 0, sizeof *out);
    status = evaluate_text(dbg, expr, &val, out->value, sizeof out->value);
    if (status != DBG_OK)
        return status;
    value_type_name(&val, out->type, sizeof out->type);
    format_short(dbg, &val, out->value, sizeof out->value);
    out->expandable = value_expandable(&val);
    return DBG_OK;
}

static void emit_child(dbg_ctx *dbg, const value *child, const char *name, const char *expr,
                       dbg_eval_child_fn fn, void *user)
{
    dbg_eval_child  entry;
    dbg_eval_result result;

    value_type_name(child, result.type, sizeof result.type);
    format_short(dbg, child, result.value, sizeof result.value);
    result.expandable = value_expandable(child);
    entry.name = name;
    entry.expr = expr;
    entry.result = &result;
    fn(user, &entry);
}

static void emit_members(dbg_ctx *dbg, const value *val, const char *base, const char *access,
                         dbg_eval_child_fn fn, void *user)
{
    const sym_type   *type;
    const sym_member *field;
    value             child;
    char              expr[EXPR_TEXT];
    uint32_t          index;

    type = real_type(val->module, val->type);
    for (index = 0; index < type->member_count; index++) {
        field = &val->module->members[type->first_member + index];
        member_value(val, field, &child);
        snprintf(expr, sizeof expr, "%s%s%s", base, access, field->name);
        emit_child(dbg, &child, field->name, expr, fn, user);
    }
}

static void emit_elements(dbg_ctx *dbg, const value *val, const char *base,
                          dbg_eval_child_fn fn, void *user)
{
    const sym_type *type;
    value           child;
    char            name[NAME_TEXT];
    char            expr[EXPR_TEXT];
    uint64_t        size;
    uint32_t        index;

    type = real_type(val->module, val->type);
    size = type_size(val->module, type->target, 0);
    for (index = 0; index < type->count && index < MAX_CHILD_ELEMENTS && size; index++) {
        element_value(val, type->target, size, index, &child);
        snprintf(name, sizeof name, "[%u]", index);
        snprintf(expr, sizeof expr, "%s[%u]", base, index);
        emit_child(dbg, &child, name, expr, fn, user);
    }
}

dbg_status dbg_eval_children(dbg_ctx *dbg, const char *expr, dbg_eval_child_fn fn, void *user)
{
    const sym_type *type;
    value           val;
    value           target;
    char            base[EXPR_TEXT];
    char            child_expr[EXPR_TEXT];
    char            error[VALUE_TEXT];
    dbg_status      status;

    status = evaluate_text(dbg, expr, &val, error, sizeof error);
    if (status != DBG_OK)
        return status;
    if (expr[0] == '*' || expr[0] == '&')
        snprintf(base, sizeof base, "(%s)", expr);
    else
        snprintf(base, sizeof base, "%s", expr);
    type = real_type(val.module, val.type);
    if (val.address_of || type->kind == SYM_TYPE_POINTER) {
        status = pointee(dbg, &val, &target);
        if (status != DBG_OK)
            return status;
        type = real_type(target.module, target.type);
        if (type->kind == SYM_TYPE_STRUCT || type->kind == SYM_TYPE_UNION) {
            emit_members(dbg, &target, base, "->", fn, user);
        } else {
            snprintf(child_expr, sizeof child_expr, "*%s", base);
            emit_child(dbg, &target, "*", child_expr, fn, user);
        }
        return DBG_OK;
    }
    if ((type->kind == SYM_TYPE_STRUCT || type->kind == SYM_TYPE_UNION) &&
        val.kind == VALUE_MEMORY)
        emit_members(dbg, &val, base, ".", fn, user);
    else if (type->kind == SYM_TYPE_ARRAY && val.kind == VALUE_MEMORY)
        emit_elements(dbg, &val, base, fn, user);
    return DBG_OK;
}
