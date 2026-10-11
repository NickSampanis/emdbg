#include "cmd.h"

#include <stdlib.h>
#include <string.h>

#define IDS_HEADER_SIZE      24u
#define IDS_DIRECTORY_ENTRY  24u
#define IDS_MAX_SECTIONS     64u

#define FILE_RECORD_SIZE     4u
#define FUNC_RECORD_SIZE     40u
#define LINE_RECORD_SIZE     24u
#define TYPE_RECORD_SIZE     28u
#define MEMB_RECORD_SIZE     24u
#define ENUM_RECORD_SIZE     16u
#define VAR_RECORD_SIZE      40u
#define LOC_RECORD_SIZE      32u
#define CFA_RECORD_SIZE      24u

typedef struct ids_section {
    const uint8_t *data;
    uint32_t       entry_size;
    uint64_t       count;
} ids_section;

typedef struct ids_reader {
    dbg_ctx       *dbg;
    sym_module    *module;
    const uint8_t *data;
    size_t         size;
    size_t         strings_size;
} ids_reader;

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)(bytes[0] | bytes[1] << 8);
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

static uint64_t read_u64(const uint8_t *bytes)
{
    return (uint64_t)read_u32(bytes) | (uint64_t)read_u32(bytes + 4) << 32;
}

static void *alloc_array(uint64_t count, size_t size)
{
    if (count > SIZE_MAX / size)
        return NULL;
    return calloc(count ? (size_t)count : 1, size);
}

static dbg_status corrupt(const ids_reader *reader, const char *what)
{
    dbg_out(reader->dbg, DBG_OUT_ERROR, "%s: corrupt .ids file (%s)\n",
            reader->module->symbol_file, what);
    return DBG_E_BADARG;
}

static dbg_status find_section(const ids_reader *reader, const char *tag, uint32_t min_entry,
                               ids_section *out)
{
    const uint8_t *entry;
    uint64_t       offset;
    uint64_t       size;
    uint32_t       entry_size;
    uint32_t       count;
    uint32_t       index;

    memset(out, 0, sizeof *out);
    count = read_u32(reader->data + 8);
    for (index = 0; index < count; index++) {
        entry = reader->data + IDS_HEADER_SIZE + index * IDS_DIRECTORY_ENTRY;
        if (memcmp(entry, tag, 4))
            continue;
        entry_size = read_u32(entry + 4);
        offset = read_u64(entry + 8);
        size = read_u64(entry + 16);
        if (offset > reader->size || size > reader->size - offset || entry_size < min_entry ||
            size % entry_size)
            return corrupt(reader, tag);
        out->data = reader->data + offset;
        out->entry_size = entry_size;
        out->count = size / entry_size;
        return DBG_OK;
    }
    return DBG_OK;
}

static const uint8_t *record_at(const ids_section *section, uint64_t index)
{
    return section->data + index * section->entry_size;
}

static const char *string_at(const ids_reader *reader, uint32_t offset)
{
    if (offset >= reader->strings_size)
        return "";
    return reader->module->strings + offset;
}

static const struct reg_def *register_at(const ids_reader *reader, uint32_t offset)
{
    const char *name;

    name = string_at(reader, offset);
    if (!*name)
        return NULL;
    return reg_find(name, strlen(name));
}

static bool range_ok(uint32_t first, uint32_t count, uint64_t total)
{
    return first <= total && count <= total - first;
}

static dbg_status read_strings(ids_reader *reader)
{
    ids_section section;
    dbg_status  status;

    status = find_section(reader, "STRS", 1, &section);
    if (status != DBG_OK)
        return status;
    reader->module->strings = malloc((size_t)section.count + 1);
    if (!reader->module->strings)
        return DBG_E_NOMEM;
    if (section.count)
        memcpy(reader->module->strings, section.data, (size_t)section.count);
    reader->module->strings[section.count] = '\0';
    reader->strings_size = (size_t)section.count;
    return DBG_OK;
}

static dbg_status read_files(ids_reader *reader)
{
    ids_section section;
    sym_module *module;
    const char *path;
    uint64_t    index;
    dbg_status  status;

    module = reader->module;
    status = find_section(reader, "FILE", FILE_RECORD_SIZE, &section);
    if (status != DBG_OK)
        return status;
    module->files = alloc_array(section.count, sizeof *module->files);
    if (!module->files)
        return DBG_E_NOMEM;
    for (index = 0; index < section.count; index++) {
        path = string_at(reader, read_u32(record_at(&section, index)));
        module->files[index].path = malloc(strlen(path) + 1);
        if (!module->files[index].path)
            return DBG_E_NOMEM;
        strcpy(module->files[index].path, path);
        module->file_count++;
    }
    return DBG_OK;
}

static dbg_status read_types(ids_reader *reader)
{
    ids_section    types;
    ids_section    members;
    ids_section    enumerators;
    sym_module    *module;
    sym_type      *type;
    const uint8_t *record;
    uint64_t       index;
    dbg_status     status;

    module = reader->module;
    status = find_section(reader, "TYPE", TYPE_RECORD_SIZE, &types);
    if (status == DBG_OK)
        status = find_section(reader, "MEMB", MEMB_RECORD_SIZE, &members);
    if (status == DBG_OK)
        status = find_section(reader, "ENUM", ENUM_RECORD_SIZE, &enumerators);
    if (status != DBG_OK)
        return status;
    if (types.count > UINT32_MAX || members.count > UINT32_MAX || enumerators.count > UINT32_MAX)
        return corrupt(reader, "too many types");

    module->types = alloc_array(types.count ? types.count : 1, sizeof *module->types);
    module->members = alloc_array(members.count, sizeof *module->members);
    module->enumerators = alloc_array(enumerators.count, sizeof *module->enumerators);
    if (!module->types || !module->members || !module->enumerators)
        return DBG_E_NOMEM;
    module->pub.type_count = types.count ? (uint32_t)types.count : 1;
    module->member_count = (uint32_t)members.count;
    module->enumerator_count = (uint32_t)enumerators.count;
    module->types[0].name = "";

    for (index = 0; index < members.count; index++) {
        record = record_at(&members, index);
        module->members[index].name = string_at(reader, read_u32(record));
        module->members[index].type = read_u32(record + 4);
        module->members[index].offset = read_u64(record + 8);
        module->members[index].bit_offset = read_u16(record + 16);
        module->members[index].bit_size = read_u16(record + 18);
        if (module->members[index].type >= module->pub.type_count)
            module->members[index].type = 0;
    }
    for (index = 0; index < enumerators.count; index++) {
        record = record_at(&enumerators, index);
        module->enumerators[index].name = string_at(reader, read_u32(record));
        module->enumerators[index].value = (int64_t)read_u64(record + 8);
    }
    for (index = 0; index < types.count; index++) {
        record = record_at(&types, index);
        type = &module->types[index];
        type->kind = record[0];
        type->flags = record[1];
        type->size = read_u32(record + 4);
        type->name = string_at(reader, read_u32(record + 8));
        type->target = read_u32(record + 12);
        type->count = read_u32(record + 16);
        type->first_member = read_u32(record + 20);
        type->member_count = read_u32(record + 24);
        if (type->kind > SYM_TYPE_TYPEDEF)
            type->kind = SYM_TYPE_NONE;
        if (type->target >= module->pub.type_count)
            type->target = 0;
        if (!range_ok(type->first_member, type->member_count,
                      type->kind == SYM_TYPE_ENUM ? enumerators.count : members.count)) {
            type->first_member = 0;
            type->member_count = 0;
        }
    }
    return DBG_OK;
}

static dbg_status read_locations(ids_reader *reader)
{
    ids_section    section;
    sym_module    *module;
    sym_location  *location;
    const uint8_t *record;
    uint64_t       index;
    dbg_status     status;

    module = reader->module;
    status = find_section(reader, "LOC ", LOC_RECORD_SIZE, &section);
    if (status != DBG_OK)
        return status;
    if (section.count > UINT32_MAX)
        return corrupt(reader, "too many locations");
    module->locations = alloc_array(section.count, sizeof *module->locations);
    if (!module->locations)
        return DBG_E_NOMEM;
    module->location_count = (uint32_t)section.count;
    for (index = 0; index < section.count; index++) {
        record = record_at(&section, index);
        location = &module->locations[index];
        location->kind = record[0] > SYM_LOC_VALUE ? SYM_LOC_NONE : record[0];
        location->reg = register_at(reader, read_u32(record + 4));
        location->offset = (int64_t)read_u64(record + 8);
        location->start = read_u64(record + 16);
        location->end = read_u64(record + 24);
        if ((location->kind == SYM_LOC_REGISTER || location->kind == SYM_LOC_REG_RELATIVE) &&
            !location->reg)
            location->kind = SYM_LOC_NONE;
    }
    return DBG_OK;
}

static dbg_status read_vars(ids_reader *reader, const char *tag, sym_var **out, uint32_t *count)
{
    ids_section    section;
    sym_module    *module;
    sym_var       *var;
    const uint8_t *record;
    uint64_t       index;
    dbg_status     status;

    module = reader->module;
    status = find_section(reader, tag, VAR_RECORD_SIZE, &section);
    if (status != DBG_OK)
        return status;
    if (section.count > UINT32_MAX)
        return corrupt(reader, "too many variables");
    *out = alloc_array(section.count, sizeof **out);
    if (!*out)
        return DBG_E_NOMEM;
    *count = (uint32_t)section.count;
    for (index = 0; index < section.count; index++) {
        record = record_at(&section, index);
        var = &(*out)[index];
        var->name = string_at(reader, read_u32(record));
        var->type = read_u32(record + 4);
        var->flags = read_u32(record + 8);
        var->first_loc = read_u32(record + 12);
        var->loc_count = read_u32(record + 16);
        var->scope_start = read_u64(record + 24);
        var->scope_end = read_u64(record + 32);
        if (var->type >= module->pub.type_count)
            var->type = 0;
        if (!range_ok(var->first_loc, var->loc_count, module->location_count)) {
            var->first_loc = 0;
            var->loc_count = 0;
        }
    }
    return DBG_OK;
}

static dbg_status read_cfas(ids_reader *reader)
{
    ids_section    section;
    sym_module    *module;
    const uint8_t *record;
    uint64_t       index;
    dbg_status     status;

    module = reader->module;
    status = find_section(reader, "CFA ", CFA_RECORD_SIZE, &section);
    if (status != DBG_OK)
        return status;
    if (section.count > UINT32_MAX)
        return corrupt(reader, "too many frame rules");
    module->cfas = alloc_array(section.count, sizeof *module->cfas);
    if (!module->cfas)
        return DBG_E_NOMEM;
    module->cfa_count = (uint32_t)section.count;
    for (index = 0; index < section.count; index++) {
        record = record_at(&section, index);
        module->cfas[index].start = read_u64(record);
        module->cfas[index].reg = register_at(reader, read_u32(record + 8));
        module->cfas[index].offset = (int64_t)read_u64(record + 16);
    }
    return DBG_OK;
}

static dbg_status read_funcs(ids_reader *reader)
{
    ids_section    section;
    sym_module    *module;
    sym_func      *func;
    const uint8_t *record;
    uint64_t       index;
    uint64_t       base;
    dbg_status     status;

    module = reader->module;
    base = module->pub.base;
    status = find_section(reader, "FUNC", FUNC_RECORD_SIZE, &section);
    if (status != DBG_OK)
        return status;
    if (section.count > UINT32_MAX)
        return corrupt(reader, "too many functions");
    module->funcs = alloc_array(section.count, sizeof *module->funcs);
    if (!module->funcs)
        return DBG_E_NOMEM;
    for (index = 0; index < section.count; index++) {
        record = record_at(&section, index);
        func = &module->funcs[module->pub.function_count];
        func->start = base + read_u64(record);
        func->end = base + read_u64(record + 8);
        func->name = string_at(reader, read_u32(record + 16));
        func->type = read_u32(record + 20);
        func->first_var = read_u32(record + 24);
        func->var_count = read_u32(record + 28);
        func->first_cfa = read_u32(record + 32);
        func->cfa_count = read_u32(record + 36);
        if (func->end <= func->start)
            func->end = func->start + 1;
        if (func->type >= module->pub.type_count)
            func->type = 0;
        if (!range_ok(func->first_var, func->var_count, module->var_count)) {
            func->first_var = 0;
            func->var_count = 0;
        }
        if (!range_ok(func->first_cfa, func->cfa_count, module->cfa_count)) {
            func->first_cfa = 0;
            func->cfa_count = 0;
        }
        module->pub.function_count++;
    }
    return DBG_OK;
}

static dbg_status read_lines(ids_reader *reader)
{
    ids_section    section;
    sym_module    *module;
    sym_line      *line;
    const uint8_t *record;
    uint64_t       index;
    uint64_t       start;
    uint64_t       end;
    uint32_t       number;
    uint32_t       file;
    dbg_status     status;

    module = reader->module;
    status = find_section(reader, "LINE", LINE_RECORD_SIZE, &section);
    if (status != DBG_OK)
        return status;
    if (section.count > UINT32_MAX)
        return corrupt(reader, "too many lines");
    module->lines = alloc_array(section.count, sizeof *module->lines);
    if (!module->lines)
        return DBG_E_NOMEM;
    for (index = 0; index < section.count; index++) {
        record = record_at(&section, index);
        start = read_u64(record);
        end = read_u64(record + 8);
        number = read_u32(record + 16);
        file = read_u32(record + 20);
        if (end <= start || number == 0 || file >= module->file_count)
            continue;
        line = &module->lines[module->pub.line_count++];
        line->start = module->pub.base + start;
        line->end = module->pub.base + end;
        line->line = number;
        line->file = file;
    }
    return DBG_OK;
}

dbg_status ids_parse_v2(dbg_ctx *dbg, sym_module *module, const uint8_t *data, size_t size)
{
    ids_reader reader;
    uint32_t   section_count;
    dbg_status status;

    memset(&reader, 0, sizeof reader);
    reader.dbg = dbg;
    reader.module = module;
    reader.data = data;
    reader.size = size;
    if (size < IDS_HEADER_SIZE)
        return corrupt(&reader, "header");
    section_count = read_u32(data + 8);
    if (section_count > IDS_MAX_SECTIONS ||
        IDS_HEADER_SIZE + (size_t)section_count * IDS_DIRECTORY_ENTRY > size)
        return corrupt(&reader, "section directory");
    module->pub.end = module->pub.base + read_u64(data + 16);

    status = read_strings(&reader);
    if (status == DBG_OK)
        status = read_files(&reader);
    if (status == DBG_OK)
        status = read_types(&reader);
    if (status == DBG_OK)
        status = read_locations(&reader);
    if (status == DBG_OK)
        status = read_vars(&reader, "VAR ", &module->vars, &module->var_count);
    if (status == DBG_OK)
        status = read_vars(&reader, "GVAR", &module->globals, &module->pub.global_count);
    if (status == DBG_OK)
        status = read_cfas(&reader);
    if (status == DBG_OK)
        status = read_funcs(&reader);
    if (status == DBG_OK)
        status = read_lines(&reader);
    return status;
}
