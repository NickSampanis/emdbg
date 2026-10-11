#include "dbg.h"

#include <stdlib.h>
#include <string.h>

#define BUILD_FNV_OFFSET  0x811c9dc5u
#define BUILD_FNV_PRIME   0x01000193u
#define BUILD_NO_SLOT     UINT32_MAX

static uint32_t hash_text(const char *text, size_t len)
{
    uint32_t hash;
    size_t   index;

    hash = BUILD_FNV_OFFSET;
    for (index = 0; index < len; index++) {
        hash ^= (uint8_t)text[index];
        hash *= BUILD_FNV_PRIME;
    }
    return hash;
}

static bool grow(sym_builder *builder, void **array, uint32_t *cap, uint32_t count, size_t size)
{
    void    *grown;
    uint32_t capacity;

    if (count < *cap)
        return true;
    capacity = *cap ? *cap * 2 : 64;
    grown = realloc(*array, (size_t)capacity * size);
    if (!grown) {
        builder->status = DBG_E_NOMEM;
        return false;
    }
    *array = grown;
    *cap = capacity;
    return true;
}

static bool rehash(sym_builder *builder)
{
    uint32_t *slots;
    uint32_t  capacity;
    uint32_t  index;
    uint32_t  slot;
    uint32_t  offset;
    size_t    len;

    capacity = builder->slot_cap ? builder->slot_cap * 2 : 1024;
    slots = malloc((size_t)capacity * sizeof *slots);
    if (!slots) {
        builder->status = DBG_E_NOMEM;
        return false;
    }
    memset(slots, 0xff, (size_t)capacity * sizeof *slots);
    for (index = 0; index < builder->slot_cap; index++) {
        offset = builder->slots[index];
        if (offset == BUILD_NO_SLOT)
            continue;
        len = strlen(builder->strings + offset);
        slot = hash_text(builder->strings + offset, len) & (capacity - 1);
        while (slots[slot] != BUILD_NO_SLOT)
            slot = (slot + 1) & (capacity - 1);
        slots[slot] = offset;
    }
    free(builder->slots);
    builder->slots = slots;
    builder->slot_cap = capacity;
    return true;
}

void symbuild_init(sym_builder *builder, sym_module *module)
{
    build_type none;

    memset(builder, 0, sizeof *builder);
    memset(&none, 0, sizeof none);
    builder->module = module;
    builder->status = DBG_OK;
    symbuild_string(builder, "", 0);
    symbuild_type(builder, &none);
}

uint32_t symbuild_string(sym_builder *builder, const char *text, size_t len)
{
    char    *grown;
    uint32_t slot;
    uint32_t offset;
    size_t   capacity;

    if (builder->status != DBG_OK)
        return 0;
    if ((builder->slot_used + 1) * 2 > builder->slot_cap && !rehash(builder))
        return 0;
    slot = hash_text(text, len) & (builder->slot_cap - 1);
    while (builder->slots[slot] != BUILD_NO_SLOT) {
        offset = builder->slots[slot];
        if (!strncmp(builder->strings + offset, text, len) && !builder->strings[offset + len])
            return offset;
        slot = (slot + 1) & (builder->slot_cap - 1);
    }
    if (builder->string_len + len + 1 > UINT32_MAX) {
        builder->status = DBG_E_NOMEM;
        return 0;
    }
    if (builder->string_len + len + 1 > builder->string_cap) {
        capacity = builder->string_cap ? builder->string_cap * 2 : 65536;
        while (capacity < builder->string_len + len + 1)
            capacity *= 2;
        grown = realloc(builder->strings, capacity);
        if (!grown) {
            builder->status = DBG_E_NOMEM;
            return 0;
        }
        builder->strings = grown;
        builder->string_cap = capacity;
    }
    offset = (uint32_t)builder->string_len;
    memcpy(builder->strings + offset, text, len);
    builder->strings[offset + len] = '\0';
    builder->string_len += len + 1;
    builder->slots[slot] = offset;
    builder->slot_used++;
    return offset;
}

uint32_t symbuild_func(sym_builder *builder, uint64_t start, uint64_t end, const char *name,
                       size_t len)
{
    build_func *func;

    if (builder->status != DBG_OK ||
        !grow(builder, (void **)&builder->funcs, &builder->func_cap, builder->func_count,
              sizeof *builder->funcs))
        return UINT32_MAX;
    func = &builder->funcs[builder->func_count];
    memset(func, 0, sizeof *func);
    func->start = start;
    func->end = end;
    func->name = symbuild_string(builder, name, len);
    if (builder->status != DBG_OK)
        return UINT32_MAX;
    return builder->func_count++;
}

void symbuild_func_vars(sym_builder *builder, uint32_t func, uint32_t first, uint32_t count)
{
    if (func >= builder->func_count)
        return;
    builder->funcs[func].first_var = first;
    builder->funcs[func].var_count = count;
}

uint32_t symbuild_type(sym_builder *builder, const build_type *type)
{
    if (builder->status != DBG_OK ||
        !grow(builder, (void **)&builder->types, &builder->type_cap, builder->type_count,
              sizeof *builder->types))
        return 0;
    builder->types[builder->type_count] = *type;
    return builder->type_count++;
}

void symbuild_type_set(sym_builder *builder, uint32_t index, const build_type *type)
{
    if (index && index < builder->type_count)
        builder->types[index] = *type;
}

uint32_t symbuild_member(sym_builder *builder, const build_member *member)
{
    if (builder->status != DBG_OK ||
        !grow(builder, (void **)&builder->members, &builder->member_cap, builder->member_count,
              sizeof *builder->members))
        return 0;
    builder->members[builder->member_count] = *member;
    return builder->member_count++;
}

uint32_t symbuild_enum(sym_builder *builder, const build_enum *value)
{
    if (builder->status != DBG_OK ||
        !grow(builder, (void **)&builder->enums, &builder->enum_cap, builder->enum_count,
              sizeof *builder->enums))
        return 0;
    builder->enums[builder->enum_count] = *value;
    return builder->enum_count++;
}

uint32_t symbuild_location(sym_builder *builder, const sym_location *location)
{
    if (builder->status != DBG_OK ||
        !grow(builder, (void **)&builder->locations, &builder->location_cap,
              builder->location_count, sizeof *builder->locations))
        return 0;
    builder->locations[builder->location_count] = *location;
    return builder->location_count++;
}

uint32_t symbuild_var(sym_builder *builder, bool global, const build_var *var)
{
    build_var **array;
    uint32_t   *count;
    uint32_t   *cap;

    array = global ? &builder->globals : &builder->vars;
    count = global ? &builder->global_count : &builder->var_count;
    cap = global ? &builder->global_cap : &builder->var_cap;
    if (builder->status != DBG_OK || !grow(builder, (void **)array, cap, *count, sizeof **array))
        return 0;
    (*array)[*count] = *var;
    return (*count)++;
}

uint32_t symbuild_file(sym_builder *builder, const char *path, size_t len)
{
    uint32_t offset;
    uint32_t index;

    offset = symbuild_string(builder, path, len);
    if (builder->status != DBG_OK)
        return 0;
    for (index = 0; index < builder->file_count; index++)
        if (builder->files[index] == offset)
            return index;
    if (!grow(builder, (void **)&builder->files, &builder->file_cap, builder->file_count,
              sizeof *builder->files))
        return 0;
    builder->files[builder->file_count] = offset;
    return builder->file_count++;
}

void symbuild_line(sym_builder *builder, uint64_t start, uint64_t end, uint32_t line,
                   uint32_t file)
{
    sym_line *entry;

    if (builder->status != DBG_OK || end <= start || !line || file >= builder->file_count ||
        !grow(builder, (void **)&builder->lines, &builder->line_cap, builder->line_count,
              sizeof *builder->lines))
        return;
    entry = &builder->lines[builder->line_count++];
    entry->start = start;
    entry->end = end;
    entry->line = line;
    entry->file = file;
}

static int compare_build_funcs(const void *left, const void *right)
{
    const build_func *left_func;
    const build_func *right_func;

    left_func = left;
    right_func = right;
    if (left_func->start != right_func->start)
        return left_func->start < right_func->start ? -1 : 1;
    if ((left_func->end != 0) != (right_func->end != 0))
        return left_func->end ? -1 : 1;
    if (left_func->var_count != right_func->var_count)
        return left_func->var_count > right_func->var_count ? -1 : 1;
    return 0;
}

static uint32_t merge_funcs(sym_builder *builder)
{
    build_func *funcs;
    uint32_t    count;
    uint32_t    index;

    funcs = builder->funcs;
    qsort(funcs, builder->func_count, sizeof *funcs, compare_build_funcs);
    count = 0;
    for (index = 0; index < builder->func_count; index++) {
        if (count && funcs[count - 1].start == funcs[index].start)
            continue;
        funcs[count++] = funcs[index];
    }
    for (index = 0; index < count; index++) {
        if (funcs[index].end > funcs[index].start)
            continue;
        if (index + 1 < count)
            funcs[index].end = funcs[index + 1].start;
        else
            funcs[index].end = funcs[index].start + 1;
    }
    return count;
}

static int compare_lines(const void *left, const void *right)
{
    const sym_line *left_line;
    const sym_line *right_line;

    left_line = left;
    right_line = right;
    if (left_line->start == right_line->start)
        return 0;
    return left_line->start < right_line->start ? -1 : 1;
}

static void clip_lines(sym_builder *builder)
{
    sym_line *lines;
    uint32_t  count;
    uint32_t  index;

    lines = builder->lines;
    qsort(lines, builder->line_count, sizeof *lines, compare_lines);
    count = 0;
    for (index = 0; index < builder->line_count; index++) {
        if (index + 1 < builder->line_count && lines[index].end > lines[index + 1].start)
            lines[index].end = lines[index + 1].start;
        if (lines[index].end > lines[index].start)
            lines[count++] = lines[index];
    }
    builder->line_count = count;
}

static dbg_status finish_types(sym_builder *builder, sym_module *module)
{
    const build_type *type;
    uint32_t          index;

    module->types = calloc(builder->type_count ? builder->type_count : 1, sizeof *module->types);
    module->members = calloc(builder->member_count ? builder->member_count : 1,
                             sizeof *module->members);
    module->enumerators = calloc(builder->enum_count ? builder->enum_count : 1,
                                 sizeof *module->enumerators);
    if (!module->types || !module->members || !module->enumerators)
        return DBG_E_NOMEM;
    for (index = 0; index < builder->type_count; index++) {
        type = &builder->types[index];
        module->types[index].kind = type->kind;
        module->types[index].flags = type->flags;
        module->types[index].size = type->size;
        module->types[index].name = module->strings + type->name;
        module->types[index].target = type->target < builder->type_count ? type->target : 0;
        module->types[index].count = type->count;
        module->types[index].first_member = type->first_member;
        module->types[index].member_count = type->member_count;
    }
    module->pub.type_count = builder->type_count ? builder->type_count : 1;
    module->types[0].name = module->strings;
    for (index = 0; index < builder->member_count; index++) {
        module->members[index].name = module->strings + builder->members[index].name;
        module->members[index].type = builder->members[index].type;
        module->members[index].offset = builder->members[index].offset;
        module->members[index].bit_offset = builder->members[index].bit_offset;
        module->members[index].bit_size = builder->members[index].bit_size;
    }
    module->member_count = builder->member_count;
    for (index = 0; index < builder->enum_count; index++) {
        module->enumerators[index].name = module->strings + builder->enums[index].name;
        module->enumerators[index].value = builder->enums[index].value;
    }
    module->enumerator_count = builder->enum_count;
    return DBG_OK;
}

static sym_var *convert_vars(const sym_builder *builder, const build_var *vars, uint32_t count)
{
    sym_var *out;
    uint32_t index;

    out = calloc(count ? count : 1, sizeof *out);
    if (!out)
        return NULL;
    for (index = 0; index < count; index++) {
        out[index].name = builder->module->strings + vars[index].name;
        out[index].type = vars[index].type < builder->type_count ? vars[index].type : 0;
        out[index].flags = vars[index].flags;
        out[index].first_loc = vars[index].first_loc;
        out[index].loc_count = vars[index].loc_count;
        out[index].scope_start = vars[index].scope_start;
        out[index].scope_end = vars[index].scope_end;
    }
    return out;
}

static dbg_status finish_vars(sym_builder *builder, sym_module *module)
{
    module->vars = convert_vars(builder, builder->vars, builder->var_count);
    module->globals = convert_vars(builder, builder->globals, builder->global_count);
    if (!module->vars || !module->globals)
        return DBG_E_NOMEM;
    module->var_count = builder->var_count;
    module->pub.global_count = builder->global_count;
    module->locations = builder->locations;
    module->location_count = builder->location_count;
    builder->locations = NULL;
    return DBG_OK;
}

dbg_status symbuild_finish(sym_builder *builder)
{
    sym_module *module;
    uint32_t    count;
    uint32_t    index;

    module = builder->module;
    if (builder->status != DBG_OK) {
        symbuild_free(builder);
        return builder->status;
    }
    count = merge_funcs(builder);
    clip_lines(builder);
    module->funcs = calloc(count ? count : 1, sizeof *module->funcs);
    module->files = calloc(builder->file_count ? builder->file_count : 1, sizeof *module->files);
    if (!module->funcs || !module->files) {
        symbuild_free(builder);
        return DBG_E_NOMEM;
    }
    module->strings = builder->strings;
    builder->strings = NULL;
    for (index = 0; index < count; index++) {
        module->funcs[index].start = builder->funcs[index].start;
        module->funcs[index].end = builder->funcs[index].end;
        module->funcs[index].name = module->strings + builder->funcs[index].name;
        module->funcs[index].first_var = builder->funcs[index].first_var;
        module->funcs[index].var_count = builder->funcs[index].var_count;
    }
    module->pub.function_count = count;
    if (finish_types(builder, module) != DBG_OK || finish_vars(builder, module) != DBG_OK) {
        symbuild_free(builder);
        return DBG_E_NOMEM;
    }
    for (index = 0; index < builder->file_count; index++) {
        module->files[index].path = malloc(strlen(module->strings + builder->files[index]) + 1);
        if (!module->files[index].path) {
            symbuild_free(builder);
            return DBG_E_NOMEM;
        }
        strcpy(module->files[index].path, module->strings + builder->files[index]);
        module->file_count++;
    }
    module->lines = builder->lines;
    module->pub.line_count = builder->line_count;
    builder->lines = NULL;
    symbuild_free(builder);
    return DBG_OK;
}

void symbuild_free(sym_builder *builder)
{
    free(builder->strings);
    free(builder->slots);
    free(builder->funcs);
    free(builder->files);
    free(builder->lines);
    free(builder->types);
    free(builder->members);
    free(builder->enums);
    free(builder->vars);
    free(builder->globals);
    free(builder->locations);
    builder->strings = NULL;
    builder->slots = NULL;
    builder->funcs = NULL;
    builder->files = NULL;
    builder->lines = NULL;
    builder->types = NULL;
    builder->members = NULL;
    builder->enums = NULL;
    builder->vars = NULL;
    builder->globals = NULL;
    builder->locations = NULL;
}
