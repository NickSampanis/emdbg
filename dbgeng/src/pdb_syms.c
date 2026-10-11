#include "pdb.h"
#include "cmd.h"

#include <stdio.h>
#include <string.h>

#define S_END                           0x0006u
#define S_FRAMEPROC                     0x1012u
#define S_THUNK32                       0x1102u
#define S_BLOCK32                       0x1103u
#define S_WITH32                        0x1104u
#define S_REGISTER                      0x1106u
#define S_CONSTANT                      0x1107u
#define S_BPREL32                       0x110bu
#define S_LDATA32                       0x110cu
#define S_GDATA32                       0x110du
#define S_LPROC32                       0x110fu
#define S_GPROC32                       0x1110u
#define S_REGREL32                      0x1111u
#define S_SEPCODE                       0x1132u
#define S_LOCAL                         0x113eu
#define S_DEFRANGE                      0x113fu
#define S_DEFRANGE_SUBFIELD             0x1140u
#define S_DEFRANGE_REGISTER             0x1141u
#define S_DEFRANGE_FRAMEPOINTER_REL     0x1142u
#define S_DEFRANGE_SUBFIELD_REGISTER    0x1143u
#define S_DEFRANGE_FRAMEPOINTER_FULL    0x1144u
#define S_DEFRANGE_REGISTER_REL         0x1145u
#define S_LPROC32_ID                    0x1146u
#define S_GPROC32_ID                    0x1147u
#define S_INLINESITE                    0x114du
#define S_INLINESITE_END                0x114eu
#define S_PROC_ID_END                   0x114fu
#define S_LPROC32_DPC                   0x1155u
#define S_LPROC32_DPC_ID                0x1156u
#define S_INLINESITE2                   0x115du

#define LOCAL_IS_PARAM                  0x0001u
#define REGISTER_REL_PARTIAL            0xfff1u
#define SCOPE_DEPTH                     64u
#define VAR_STACK_RELATIVE              0x80000000u
#define NO_FUNC                         UINT32_MAX

#define CV_AMD64_SIL                    324u
#define CV_AMD64_RAX                    328u
#define CV_AMD64_R8                     336u
#define CV_AMD64_R8B                    344u
#define CV_AMD64_R8W                    352u
#define CV_AMD64_R8D                    360u
#define CV_AMD64_R15D                   367u
#define CV_X86_EDI                      24u

typedef struct scope {
    uint16_t kind;
    uint64_t start;
    uint64_t end;
} scope;

typedef struct symbol_walk {
    pdb_reader     *reader;
    scope           scopes[SCOPE_DEPTH];
    uint32_t        depth;
    uint32_t        inline_depth;
    uint32_t        func;
    uint32_t        first_var;
    uint32_t        local;
    bool            have_local;
    uint32_t        frame_size;
    uint32_t        saved_size;
    const reg_def  *local_base;
    const reg_def  *param_base;
    const reg_def  *stack_reg;
} symbol_walk;

static const char *const cv_x86_names[] = {
    NULL,  "al",  "cl",  "dl",  "bl",  "ah",  "ch",  "dh",  "bh",  "ax",  "cx",  "dx",  "bx",
    "sp",  "bp",  "si",  "di",  "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
};

static const char *const cv_amd64_names[] = {
    "sil", "dil", "bpl", "spl", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
};

static const char *const cv_amd64_high[] = { "r%u", "r%ub", "r%uw", "r%ud" };

static bool is_x86(const pdb_reader *reader)
{
    return reader->machine == PDB_MACHINE_X86;
}

static const reg_def *cv_register(uint16_t number)
{
    char     name[8];
    uint32_t group;

    if (number && number <= CV_X86_EDI)
        return reg_find(cv_x86_names[number], strlen(cv_x86_names[number]));
    if (number >= CV_AMD64_SIL && number < CV_AMD64_R8)
        return reg_find(cv_amd64_names[number - CV_AMD64_SIL],
                        strlen(cv_amd64_names[number - CV_AMD64_SIL]));
    if (number < CV_AMD64_R8 || number > CV_AMD64_R15D)
        return NULL;
    group = (number - CV_AMD64_R8) / 8;
    snprintf(name, sizeof name, cv_amd64_high[group], 8 + (number - CV_AMD64_R8) % 8);
    return reg_find(name, strlen(name));
}

static const reg_def *frame_base(const pdb_reader *reader, uint32_t encoded)
{
    static const char *const x64_bases[] = { NULL, "rsp", "rbp", "r13" };
    static const char *const x86_bases[] = { NULL, NULL, "ebp", "ebx" };
    const char              *name;

    name = is_x86(reader) ? x86_bases[encoded & 3] : x64_bases[encoded & 3];
    return name ? reg_find(name, strlen(name)) : NULL;
}

static bool is_proc(uint16_t kind)
{
    return kind == S_GPROC32 || kind == S_LPROC32 || kind == S_GPROC32_ID ||
           kind == S_LPROC32_ID || kind == S_LPROC32_DPC || kind == S_LPROC32_DPC_ID;
}

static bool is_inline(uint16_t kind)
{
    return kind == S_INLINESITE || kind == S_INLINESITE2;
}

static bool opens_scope(uint16_t kind)
{
    return is_proc(kind) || is_inline(kind) || kind == S_THUNK32 || kind == S_BLOCK32 ||
           kind == S_WITH32 || kind == S_SEPCODE;
}

static bool is_defrange(uint16_t kind)
{
    return kind >= S_DEFRANGE && kind <= S_DEFRANGE_REGISTER_REL;
}

static void push_scope(symbol_walk *walk, uint16_t kind, uint64_t start, uint64_t end)
{
    if (walk->depth < SCOPE_DEPTH) {
        walk->scopes[walk->depth].kind = kind;
        walk->scopes[walk->depth].start = start;
        walk->scopes[walk->depth].end = end;
    }
    walk->depth++;
    if (is_inline(kind))
        walk->inline_depth++;
}

static bool add_var(symbol_walk *walk, const char *name, size_t len, uint32_t type,
                    uint32_t flags, uint32_t *out)
{
    sym_builder *builder;
    build_var    var;
    const scope *inner;

    builder = &walk->reader->builder;
    memset(&var, 0, sizeof var);
    var.name = symbuild_string(builder, name, len);
    var.type = pdb_type(walk->reader, type);
    var.flags = flags;
    var.first_loc = builder->location_count;
    if (walk->depth > 1 && walk->depth <= SCOPE_DEPTH) {
        inner = &walk->scopes[walk->depth - 1];
        if (inner->kind == S_BLOCK32) {
            var.scope_start = inner->start;
            var.scope_end = inner->end;
        }
    }
    *out = symbuild_var(builder, false, &var);
    return builder->status == DBG_OK;
}

static void add_location(symbol_walk *walk, uint32_t var, uint8_t kind, const reg_def *reg,
                         int64_t offset, uint64_t start, uint64_t end)
{
    sym_builder *builder;
    sym_location location;

    builder = &walk->reader->builder;
    memset(&location, 0, sizeof location);
    location.kind = kind;
    location.reg = reg;
    location.offset = offset;
    location.start = start;
    location.end = end;
    symbuild_location(builder, &location);
    if (builder->status == DBG_OK)
        builder->vars[var].loc_count++;
}

static void add_ranges(symbol_walk *walk, uint8_t kind, const reg_def *reg, int64_t offset,
                       const uint8_t *range, const uint8_t *gaps, uint32_t gap_bytes)
{
    uint64_t start;
    uint64_t end;
    uint64_t piece;
    uint64_t gap_start;
    uint64_t gap_end;
    uint32_t gap;

    if (!pdb_section_rva(walk->reader, read_u16(range + 4), read_u32(range), &start))
        return;
    end = start + read_u16(range + 6);
    piece = start;
    for (gap = 0; gap + 4 <= gap_bytes; gap += 4) {
        gap_start = start + read_u16(gaps + gap);
        gap_end = gap_start + read_u16(gaps + gap + 2);
        if (gap_start > piece)
            add_location(walk, walk->local, kind, reg, offset, piece,
                         gap_start < end ? gap_start : end);
        if (gap_end > piece)
            piece = gap_end;
    }
    if (end > piece)
        add_location(walk, walk->local, kind, reg, offset, piece, end);
}

static void read_defrange(symbol_walk *walk, uint16_t kind, const uint8_t *data, uint32_t len)
{
    const reg_def *reg;

    switch (kind) {
        case S_DEFRANGE_REGISTER:
            if (len < 12)
                return;
            reg = cv_register(read_u16(data));
            if (reg)
                add_ranges(walk, SYM_LOC_REGISTER, reg, 0, data + 4, data + 12, len - 12);
            return;
        case S_DEFRANGE_FRAMEPOINTER_REL:
            if (len < 12)
                return;
            add_ranges(walk, SYM_LOC_REG_RELATIVE, NULL, (int32_t)read_u32(data), data + 4,
                       data + 12, len - 12);
            return;
        case S_DEFRANGE_FRAMEPOINTER_FULL:
            if (len < 4)
                return;
            add_location(walk, walk->local, SYM_LOC_REG_RELATIVE, NULL, (int32_t)read_u32(data),
                         0, 0);
            return;
        case S_DEFRANGE_REGISTER_REL:
            if (len < 16 || (read_u16(data + 2) & REGISTER_REL_PARTIAL))
                return;
            reg = cv_register(read_u16(data));
            if (reg)
                add_ranges(walk, SYM_LOC_REG_RELATIVE, reg, (int32_t)read_u32(data + 4), data + 8,
                           data + 16, len - 16);
            return;
    }
}

static void open_proc(symbol_walk *walk, const uint8_t *data, uint32_t len)
{
    pdb_reader *reader;
    const char *name;
    size_t      name_len;
    uint64_t    rva;
    uint64_t    base;

    reader = walk->reader;
    walk->func = NO_FUNC;
    walk->frame_size = 0;
    walk->saved_size = 0;
    walk->local_base = NULL;
    walk->param_base = NULL;
    if (len < 35 || !pdb_section_rva(reader, read_u16(data + 32), read_u32(data + 28), &rva) ||
        !pdb_name(data + 35, len - 35, &name, &name_len)) {
        push_scope(walk, S_GPROC32, 0, 0);
        return;
    }
    base = reader->module->pub.base;
    push_scope(walk, S_GPROC32, rva, rva + read_u32(data + 12));
    walk->func = symbuild_func(&reader->builder, base + rva, base + rva + read_u32(data + 12),
                               name, name_len);
    walk->first_var = reader->builder.var_count;
}

static void classify_stack_var(symbol_walk *walk, build_var *var)
{
    const sym_location *location;
    int64_t             params_at;

    var->flags &= ~VAR_STACK_RELATIVE;
    if (!var->loc_count)
        return;
    location = &walk->reader->builder.locations[var->first_loc];
    params_at = (int64_t)walk->frame_size + walk->saved_size + (is_x86(walk->reader) ? 4 : 8);
    if (location->reg == walk->stack_reg && location->offset >= params_at)
        var->flags = (var->flags & ~SYM_VAR_LOCAL) | SYM_VAR_PARAM;
}

static bool described_elsewhere(const sym_builder *builder, uint32_t first, uint32_t index)
{
    uint32_t other;

    if (!(builder->vars[index].flags & VAR_STACK_RELATIVE))
        return false;
    for (other = first; other < builder->var_count; other++)
        if (other != index && builder->vars[other].name == builder->vars[index].name &&
            !(builder->vars[other].flags & VAR_STACK_RELATIVE))
            return true;
    return false;
}

static void drop_duplicates(symbol_walk *walk)
{
    sym_builder *builder;
    uint32_t     index;
    uint32_t     kept;

    builder = &walk->reader->builder;
    kept = walk->first_var;
    for (index = walk->first_var; index < builder->var_count; index++)
        if (!described_elsewhere(builder, walk->first_var, index))
            builder->vars[kept++] = builder->vars[index];
    builder->var_count = kept;
}

static void close_proc(symbol_walk *walk)
{
    sym_builder  *builder;
    build_var    *var;
    sym_location *location;
    uint32_t      index;
    uint32_t      slot;

    builder = &walk->reader->builder;
    if (walk->func == NO_FUNC || builder->status != DBG_OK)
        return;
    drop_duplicates(walk);
    for (index = walk->first_var; index < builder->var_count; index++) {
        var = &builder->vars[index];
        for (slot = 0; slot < var->loc_count; slot++) {
            location = &builder->locations[var->first_loc + slot];
            if (location->kind != SYM_LOC_REG_RELATIVE || location->reg)
                continue;
            location->reg = var->flags & SYM_VAR_PARAM ? walk->param_base : walk->local_base;
            if (!location->reg)
                location->kind = SYM_LOC_NONE;
        }
        if (var->flags & VAR_STACK_RELATIVE)
            classify_stack_var(walk, var);
    }
    symbuild_func_vars(builder, walk->func, walk->first_var, builder->var_count - walk->first_var);
    walk->func = NO_FUNC;
}

static void pop_scope(symbol_walk *walk)
{
    uint16_t kind;

    if (!walk->depth)
        return;
    walk->depth--;
    kind = walk->depth < SCOPE_DEPTH ? walk->scopes[walk->depth].kind : S_BLOCK32;
    if (is_inline(kind) && walk->inline_depth)
        walk->inline_depth--;
    if (is_proc(kind))
        close_proc(walk);
}

static void read_frameproc(symbol_walk *walk, const uint8_t *data, uint32_t len)
{
    uint32_t flags;

    if (len < 26)
        return;
    walk->frame_size = read_u32(data);
    walk->saved_size = read_u32(data + 12);
    flags = read_u32(data + 22);
    walk->local_base = frame_base(walk->reader, flags >> 14);
    walk->param_base = frame_base(walk->reader, flags >> 16);
}

static void read_variable(symbol_walk *walk, uint16_t kind, const uint8_t *data, uint32_t len)
{
    const reg_def *reg;
    const char    *name;
    size_t         name_len;
    int64_t        value;
    uint64_t       rva;
    uint32_t       used;
    uint32_t       var;

    switch (kind) {
        case S_LOCAL:
            if (len < 6 || !pdb_name(data + 6, len - 6, &name, &name_len))
                return;
            walk->have_local = add_var(walk, name, name_len, read_u32(data),
                                       read_u16(data + 4) & LOCAL_IS_PARAM ? SYM_VAR_PARAM
                                                                           : SYM_VAR_LOCAL,
                                       &walk->local);
            return;
        case S_REGREL32:
            if (len < 10 || !pdb_name(data + 10, len - 10, &name, &name_len))
                return;
            reg = cv_register(read_u16(data + 8));
            if (!add_var(walk, name, name_len, read_u32(data + 4),
                         SYM_VAR_LOCAL | (reg == walk->stack_reg ? VAR_STACK_RELATIVE : 0), &var))
                return;
            add_location(walk, var, reg ? SYM_LOC_REG_RELATIVE : SYM_LOC_NONE, reg,
                         (int32_t)read_u32(data), 0, 0);
            return;
        case S_BPREL32:
            if (len < 8 || !pdb_name(data + 8, len - 8, &name, &name_len))
                return;
            value = (int32_t)read_u32(data);
            if (!add_var(walk, name, name_len, read_u32(data + 4),
                         is_x86(walk->reader) && value > 0 ? SYM_VAR_PARAM : SYM_VAR_LOCAL, &var))
                return;
            reg = reg_find(is_x86(walk->reader) ? "ebp" : "rbp", 3);
            add_location(walk, var, SYM_LOC_REG_RELATIVE, reg, value, 0, 0);
            return;
        case S_REGISTER:
            if (len < 6 || !pdb_name(data + 6, len - 6, &name, &name_len))
                return;
            reg = cv_register(read_u16(data + 4));
            if (add_var(walk, name, name_len, read_u32(data), SYM_VAR_LOCAL, &var))
                add_location(walk, var, reg ? SYM_LOC_REGISTER : SYM_LOC_NONE, reg, 0, 0, 0);
            return;
        case S_CONSTANT:
            if (len < 4)
                return;
            used = pdb_numeric(data + 4, len - 4, &value);
            if (!used || !pdb_name(data + 4 + used, len - 4 - used, &name, &name_len))
                return;
            if (add_var(walk, name, name_len, read_u32(data), SYM_VAR_LOCAL, &var))
                add_location(walk, var, SYM_LOC_VALUE, NULL, value, 0, 0);
            return;
        case S_LDATA32:
        case S_GDATA32:
            if (len < 10 || !pdb_name(data + 10, len - 10, &name, &name_len) || !name_len ||
                !pdb_section_rva(walk->reader, read_u16(data + 8), read_u32(data + 4), &rva))
                return;
            if (add_var(walk, name, name_len, read_u32(data), SYM_VAR_LOCAL | SYM_VAR_STATIC,
                        &var))
                add_location(walk, var, SYM_LOC_ABSOLUTE, NULL, (int64_t)rva, 0, 0);
            return;
    }
}

void pdb_module_symbols(pdb_reader *reader, const uint8_t *symbols, uint32_t size)
{
    symbol_walk    walk;
    const uint8_t *record;
    const uint8_t *data;
    uint32_t       offset;
    uint32_t       len;
    uint16_t       length;
    uint16_t       kind;
    uint64_t       start;

    memset(&walk, 0, sizeof walk);
    walk.reader = reader;
    walk.func = NO_FUNC;
    walk.stack_reg = reg_find(is_x86(reader) ? "esp" : "rsp", 3);
    for (offset = 0; offset + 4 <= size && reader->builder.status == DBG_OK;
         offset += length + 2u) {
        record = symbols + offset;
        length = read_u16(record);
        kind = read_u16(record + 2);
        if (length < 2 || length > size - offset - 2)
            break;
        data = record + 4;
        len = length - 2u;
        if (!is_defrange(kind))
            walk.have_local = false;
        if (kind == S_END || kind == S_PROC_ID_END || kind == S_INLINESITE_END) {
            pop_scope(&walk);
            continue;
        }
        if (is_proc(kind) && !walk.depth) {
            open_proc(&walk, data, len);
            continue;
        }
        if (kind == S_BLOCK32 && len >= 18 &&
            pdb_section_rva(reader, read_u16(data + 16), read_u32(data + 12), &start)) {
            push_scope(&walk, kind, start, start + read_u32(data + 8));
            continue;
        }
        if (opens_scope(kind)) {
            push_scope(&walk, kind, 0, 0);
            continue;
        }
        if (walk.func == NO_FUNC || walk.inline_depth)
            continue;
        if (kind == S_FRAMEPROC)
            read_frameproc(&walk, data, len);
        else if (is_defrange(kind) && walk.have_local)
            read_defrange(&walk, kind, data, len);
        else
            read_variable(&walk, kind, data, len);
    }
    while (walk.depth)
        pop_scope(&walk);
}

void pdb_global_data(pdb_reader *reader, const uint8_t *data, uint16_t kind, uint32_t len)
{
    sym_builder *builder;
    build_var    var;
    sym_location location;
    const char  *name;
    size_t       name_len;
    uint64_t     rva;

    builder = &reader->builder;
    if (len < 10 || !pdb_name(data + 10, len - 10, &name, &name_len) || !name_len ||
        !pdb_section_rva(reader, read_u16(data + 8), read_u32(data + 4), &rva))
        return;
    memset(&var, 0, sizeof var);
    memset(&location, 0, sizeof location);
    location.kind = SYM_LOC_ABSOLUTE;
    location.offset = (int64_t)rva;
    var.name = symbuild_string(builder, name, name_len);
    var.type = pdb_type(reader, read_u32(data));
    var.flags = kind == S_GDATA32 ? SYM_VAR_GLOBAL : SYM_VAR_GLOBAL | SYM_VAR_STATIC;
    var.first_loc = symbuild_location(builder, &location);
    var.loc_count = 1;
    symbuild_var(builder, true, &var);
}
