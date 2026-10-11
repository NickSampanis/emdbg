#include "pdb.h"

#include <stdlib.h>
#include <string.h>

#define PDB_STREAM_TPI       2u
#define TPI_HEADER_MIN       56u
#define TYPE_FIRST           0x1000u
#define TYPE_DEPTH           32
#define FIELD_LIST_CHAIN     64u
#define NO_RECORD            0xffffffffu

#define LF_MODIFIER          0x1001u
#define LF_POINTER           0x1002u
#define LF_PROCEDURE         0x1008u
#define LF_MFUNCTION         0x1009u
#define LF_FIELDLIST         0x1203u
#define LF_BITFIELD          0x1205u
#define LF_BCLASS            0x1400u
#define LF_VBCLASS           0x1401u
#define LF_IVBCLASS          0x1402u
#define LF_INDEX             0x1404u
#define LF_VFUNCTAB          0x1409u
#define LF_FRIENDCLS         0x140bu
#define LF_VFUNCOFF          0x140cu
#define LF_ENUMERATE         0x1502u
#define LF_ARRAY             0x1503u
#define LF_CLASS             0x1504u
#define LF_STRUCTURE         0x1505u
#define LF_UNION             0x1506u
#define LF_ENUM              0x1507u
#define LF_FRIENDFCN         0x150cu
#define LF_MEMBER            0x150du
#define LF_STMEMBER          0x150eu
#define LF_METHOD            0x150fu
#define LF_NESTTYPE          0x1510u
#define LF_ONEMETHOD         0x1511u
#define LF_INTERFACE         0x1519u
#define LF_PAD0              0xf0u

#define LF_NUMERIC           0x8000u
#define LF_CHAR              0x8000u
#define LF_SHORT             0x8001u
#define LF_USHORT            0x8002u
#define LF_LONG              0x8003u
#define LF_ULONG             0x8004u
#define LF_QUADWORD          0x8009u
#define LF_UQUADWORD         0x800au
#define LF_VARSTRING         0x8010u
#define LF_UTF8STRING        0x801bu

#define PROP_FWDREF          0x0080u
#define PROP_UNIQUE_NAME     0x0200u
#define MODIFIER_CONST       0x0001u
#define MODIFIER_VOLATILE    0x0002u
#define POINTER_VOLATILE     0x0200u
#define POINTER_CONST        0x0400u
#define METHOD_INTRO         4u
#define METHOD_PURE_INTRO    6u

typedef struct simple_type {
    uint8_t     code;
    uint8_t     kind;
    uint8_t     flags;
    uint8_t     size;
    const char *name;
} simple_type;

typedef struct numeric_size {
    uint16_t leaf;
    uint8_t  size;
} numeric_size;

typedef struct aggregate {
    uint8_t     kind;
    uint16_t    property;
    uint32_t    field;
    uint32_t    underlying;
    int64_t     size;
    const char *name;
    size_t      name_len;
    const char *key;
    size_t      key_len;
} aggregate;

static const simple_type simple_types[] = {
    { 0x03, SYM_TYPE_VOID, 0, 0, "void" },
    { 0x08, SYM_TYPE_INT, 0, 4, "HRESULT" },
    { 0x10, SYM_TYPE_INT, SYM_TYPE_CHAR, 1, "signed char" },
    { 0x20, SYM_TYPE_UINT, SYM_TYPE_CHAR, 1, "unsigned char" },
    { 0x70, SYM_TYPE_INT, SYM_TYPE_CHAR, 1, "char" },
    { 0x71, SYM_TYPE_UINT, SYM_TYPE_CHAR, 2, "wchar_t" },
    { 0x7a, SYM_TYPE_UINT, SYM_TYPE_CHAR, 2, "char16_t" },
    { 0x7b, SYM_TYPE_UINT, 0, 4, "char32_t" },
    { 0x7c, SYM_TYPE_UINT, SYM_TYPE_CHAR, 1, "char8_t" },
    { 0x68, SYM_TYPE_INT, 0, 1, "__int8" },
    { 0x69, SYM_TYPE_UINT, 0, 1, "unsigned __int8" },
    { 0x11, SYM_TYPE_INT, 0, 2, "short" },
    { 0x21, SYM_TYPE_UINT, 0, 2, "unsigned short" },
    { 0x72, SYM_TYPE_INT, 0, 2, "__int16" },
    { 0x73, SYM_TYPE_UINT, 0, 2, "unsigned __int16" },
    { 0x12, SYM_TYPE_INT, 0, 4, "long" },
    { 0x22, SYM_TYPE_UINT, 0, 4, "unsigned long" },
    { 0x74, SYM_TYPE_INT, 0, 4, "int" },
    { 0x75, SYM_TYPE_UINT, 0, 4, "unsigned int" },
    { 0x13, SYM_TYPE_INT, 0, 8, "__int64" },
    { 0x23, SYM_TYPE_UINT, 0, 8, "unsigned __int64" },
    { 0x76, SYM_TYPE_INT, 0, 8, "__int64" },
    { 0x77, SYM_TYPE_UINT, 0, 8, "unsigned __int64" },
    { 0x14, SYM_TYPE_INT, 0, 16, "__int128" },
    { 0x24, SYM_TYPE_UINT, 0, 16, "unsigned __int128" },
    { 0x78, SYM_TYPE_INT, 0, 16, "__int128" },
    { 0x79, SYM_TYPE_UINT, 0, 16, "unsigned __int128" },
    { 0x46, SYM_TYPE_FLOAT, 0, 2, "half" },
    { 0x40, SYM_TYPE_FLOAT, 0, 4, "float" },
    { 0x41, SYM_TYPE_FLOAT, 0, 8, "double" },
    { 0x42, SYM_TYPE_FLOAT, 0, 10, "long double" },
    { 0x30, SYM_TYPE_BOOL, 0, 1, "bool" },
    { 0x31, SYM_TYPE_BOOL, 0, 2, "bool16" },
    { 0x32, SYM_TYPE_BOOL, 0, 4, "bool32" },
    { 0x33, SYM_TYPE_BOOL, 0, 8, "bool64" },
};

static const numeric_size numeric_sizes[] = {
    { 0x8005, 4 },  { 0x8006, 8 },  { 0x8007, 10 }, { 0x8008, 16 }, { 0x800b, 6 },
    { 0x800c, 8 },  { 0x800d, 16 }, { 0x800e, 20 }, { 0x800f, 32 }, { 0x8017, 16 },
    { 0x8018, 16 }, { 0x8019, 16 }, { 0x801a, 8 },  { 0x801c, 2 },
};

static const uint8_t simple_pointer_sizes[8] = { 0, 2, 4, 4, 4, 4, 8, 16 };

static uint32_t convert(pdb_reader *reader, uint32_t index, int depth);

uint32_t pdb_numeric(const uint8_t *data, uint32_t len, int64_t *value)
{
    uint16_t leaf;
    uint32_t index;

    *value = 0;
    if (len < 2)
        return 0;
    leaf = read_u16(data);
    if (leaf < LF_NUMERIC) {
        *value = leaf;
        return 2;
    }
    switch (leaf) {
        case LF_CHAR:
            if (len < 3)
                return 0;
            *value = (int8_t)data[2];
            return 3;
        case LF_SHORT:
        case LF_USHORT:
            if (len < 4)
                return 0;
            *value = leaf == LF_SHORT ? (int16_t)read_u16(data + 2) : read_u16(data + 2);
            return 4;
        case LF_LONG:
        case LF_ULONG:
            if (len < 6)
                return 0;
            *value = leaf == LF_LONG ? (int32_t)read_u32(data + 2) : read_u32(data + 2);
            return 6;
        case LF_QUADWORD:
        case LF_UQUADWORD:
            if (len < 10)
                return 0;
            *value = (int64_t)((uint64_t)read_u32(data + 2) | (uint64_t)read_u32(data + 6) << 32);
            return 10;
        case LF_VARSTRING:
            if (len < 4 || read_u16(data + 2) > len - 4)
                return 0;
            return 4u + read_u16(data + 2);
        case LF_UTF8STRING:
            if (!memchr(data + 2, '\0', len - 2))
                return 0;
            return 3u + (uint32_t)strlen((const char *)data + 2);
    }
    for (index = 0; index < sizeof numeric_sizes / sizeof numeric_sizes[0]; index++)
        if (numeric_sizes[index].leaf == leaf)
            return len - 2 >= numeric_sizes[index].size ? 2u + numeric_sizes[index].size : 0;
    return 0;
}

bool pdb_name(const uint8_t *data, uint32_t len, const char **text, size_t *text_len)
{
    const uint8_t *end;

    end = memchr(data, '\0', len);
    if (!end)
        return false;
    *text = (const char *)data;
    *text_len = (size_t)(end - data);
    return true;
}

static bool record_of(const pdb_types *types, uint32_t index, uint16_t *kind,
                      const uint8_t **data, uint32_t *len)
{
    const uint8_t *record;
    uint32_t       offset;

    if (index < types->first || index - types->first >= types->count)
        return false;
    offset = types->offsets[index - types->first];
    if (offset == NO_RECORD)
        return false;
    record = types->stream.data + offset;
    *kind = read_u16(record + 2);
    *data = record + 4;
    *len = read_u16(record) - 2u;
    return true;
}

static uint32_t type_string(pdb_reader *reader, const char *name, size_t len)
{
    static const char *const anonymous[] = { "<unnamed-", "<anonymous-", "__unnamed" };
    size_t                   index;
    size_t                   prefix;

    for (index = 0; index < sizeof anonymous / sizeof anonymous[0]; index++) {
        prefix = strlen(anonymous[index]);
        if (len >= prefix && !memcmp(name, anonymous[index], prefix))
            return 0;
    }
    return symbuild_string(&reader->builder, name, len);
}

static bool read_aggregate(uint16_t kind, const uint8_t *data, uint32_t len, aggregate *out)
{
    uint32_t used;
    uint32_t fixed;

    memset(out, 0, sizeof *out);
    if (len < 4)
        return false;
    out->property = read_u16(data + 2);
    switch (kind) {
        case LF_CLASS:
        case LF_STRUCTURE:
        case LF_INTERFACE:
            out->kind = SYM_TYPE_STRUCT;
            fixed = 16;
            break;
        case LF_UNION:
            out->kind = SYM_TYPE_UNION;
            fixed = 8;
            break;
        case LF_ENUM:
            out->kind = SYM_TYPE_ENUM;
            fixed = 12;
            break;
        default:
            return false;
    }
    if (len < fixed)
        return false;
    if (kind == LF_ENUM) {
        out->underlying = read_u32(data + 4);
        out->field = read_u32(data + 8);
        used = fixed;
    } else {
        out->field = read_u32(data + 4);
        used = pdb_numeric(data + fixed, len - fixed, &out->size);
        if (!used)
            return false;
        used += fixed;
    }
    if (!pdb_name(data + used, len - used, &out->name, &out->name_len))
        return false;
    out->key = out->name;
    out->key_len = out->name_len;
    used += (uint32_t)out->name_len + 1;
    if (out->property & PROP_UNIQUE_NAME)
        pdb_name(data + used, len - used, &out->key, &out->key_len);
    return true;
}

static uint32_t hash_key(const char *key, size_t len)
{
    uint32_t hash;
    size_t   index;

    hash = 2166136261u;
    for (index = 0; index < len; index++)
        hash = (hash ^ (uint8_t)key[index]) * 16777619u;
    return hash;
}

static void build_names(pdb_reader *reader)
{
    pdb_types      *types;
    pdb_name_slot  *slot;
    const uint8_t  *data;
    aggregate       agg;
    uint32_t        len;
    uint32_t        index;
    uint32_t        position;
    uint16_t        kind;

    types = &reader->types;
    types->names_built = true;
    types->name_cap = 16;
    while (types->name_cap < types->count * 2)
        types->name_cap *= 2;
    types->names = calloc(types->name_cap, sizeof *types->names);
    if (!types->names)
        return;
    for (index = types->first; index - types->first < types->count; index++) {
        if (!record_of(types, index, &kind, &data, &len) || !read_aggregate(kind, data, len, &agg))
            continue;
        if ((agg.property & PROP_FWDREF) || !agg.key_len)
            continue;
        position = hash_key(agg.key, agg.key_len) & (types->name_cap - 1);
        for (;;) {
            slot = &types->names[position];
            if (!slot->type) {
                slot->key = agg.key;
                slot->len = (uint32_t)agg.key_len;
                slot->type = index;
                break;
            }
            if (slot->len == agg.key_len && !memcmp(slot->key, agg.key, agg.key_len))
                break;
            position = (position + 1) & (types->name_cap - 1);
        }
    }
}

static uint32_t find_definition(pdb_reader *reader, const aggregate *agg)
{
    pdb_types           *types;
    const pdb_name_slot *slot;
    uint32_t             position;

    types = &reader->types;
    if (!types->names_built)
        build_names(reader);
    if (!types->names || !agg->key_len)
        return 0;
    position = hash_key(agg->key, agg->key_len) & (types->name_cap - 1);
    for (;;) {
        slot = &types->names[position];
        if (!slot->type)
            return 0;
        if (slot->len == agg->key_len && !memcmp(slot->key, agg->key, agg->key_len))
            return slot->type;
        position = (position + 1) & (types->name_cap - 1);
    }
}

static uint32_t simple(pdb_reader *reader, uint32_t index)
{
    build_type type;
    uint32_t   entry;
    uint32_t   target;
    uint32_t   mode;

    if (reader->types.simple[index])
        return reader->types.simple[index];
    memset(&type, 0, sizeof type);
    mode = (index >> 8) & 0x0f;
    if (mode) {
        target = simple(reader, index & 0xff);
        if (mode >= sizeof simple_pointer_sizes)
            return 0;
        type.kind = SYM_TYPE_POINTER;
        type.size = simple_pointer_sizes[mode];
        type.target = target;
    } else {
        for (entry = 0; entry < sizeof simple_types / sizeof simple_types[0]; entry++)
            if (simple_types[entry].code == index)
                break;
        if (entry == sizeof simple_types / sizeof simple_types[0])
            return 0;
        type.kind = simple_types[entry].kind;
        type.flags = simple_types[entry].flags;
        type.size = simple_types[entry].size;
        type.name = symbuild_string(&reader->builder, simple_types[entry].name,
                                    strlen(simple_types[entry].name));
    }
    reader->types.simple[index] = symbuild_type(&reader->builder, &type);
    return reader->types.simple[index];
}

static const build_type *built(const pdb_reader *reader, uint32_t index)
{
    return &reader->builder.types[index];
}

static void queue_pending(pdb_reader *reader, uint32_t index)
{
    pdb_types *types;
    uint32_t  *grown;
    uint32_t   cap;

    types = &reader->types;
    if (types->pending_count == types->pending_cap) {
        cap = types->pending_cap ? types->pending_cap * 2 : 64;
        grown = realloc(types->pending, cap * sizeof *grown);
        if (!grown) {
            reader->builder.status = DBG_E_NOMEM;
            return;
        }
        types->pending = grown;
        types->pending_cap = cap;
    }
    types->pending[types->pending_count++] = index;
}

static bool next_field(const uint8_t *data, uint32_t len, uint32_t *offset)
{
    while (*offset < len && data[*offset] >= LF_PAD0)
        *offset += (data[*offset] & 0x0f) ? (data[*offset] & 0x0fu) : 1u;
    return *offset + 2 <= len;
}

static uint32_t skip_name(const uint8_t *data, uint32_t len, uint32_t offset)
{
    const char *text;
    size_t      text_len;

    if (offset > len || !pdb_name(data + offset, len - offset, &text, &text_len))
        return 0;
    return offset + (uint32_t)text_len + 1;
}

static uint32_t skip_numeric(const uint8_t *data, uint32_t len, uint32_t offset, int64_t *value)
{
    uint32_t used;

    if (offset > len)
        return 0;
    used = pdb_numeric(data + offset, len - offset, value);
    return used ? offset + used : 0;
}

static uint32_t field_end(const uint8_t *data, uint32_t len, uint32_t offset)
{
    int64_t  ignored;
    uint32_t at;
    uint16_t leaf;

    leaf = read_u16(data + offset);
    switch (leaf) {
        case LF_MEMBER:
            at = skip_numeric(data, len, offset + 8, &ignored);
            return at ? skip_name(data, len, at) : 0;
        case LF_ENUMERATE:
            at = skip_numeric(data, len, offset + 4, &ignored);
            return at ? skip_name(data, len, at) : 0;
        case LF_BCLASS:
            return skip_numeric(data, len, offset + 8, &ignored);
        case LF_VBCLASS:
        case LF_IVBCLASS:
            at = skip_numeric(data, len, offset + 12, &ignored);
            return at ? skip_numeric(data, len, at, &ignored) : 0;
        case LF_INDEX:
        case LF_VFUNCTAB:
        case LF_FRIENDCLS:
            return offset + 8 <= len ? offset + 8 : 0;
        case LF_VFUNCOFF:
            return offset + 12 <= len ? offset + 12 : 0;
        case LF_STMEMBER:
        case LF_METHOD:
        case LF_NESTTYPE:
        case LF_FRIENDFCN:
            return skip_name(data, len, offset + 8);
        case LF_ONEMETHOD:
            if (offset + 8 > len)
                return 0;
            at = (read_u16(data + offset + 2) >> 2 & 7) == METHOD_INTRO ||
                         (read_u16(data + offset + 2) >> 2 & 7) == METHOD_PURE_INTRO
                     ? offset + 12
                     : offset + 8;
            return skip_name(data, len, at);
    }
    return 0;
}

static void add_member(pdb_reader *reader, const uint8_t *field, uint32_t len)
{
    build_member   member;
    const uint8_t *data;
    const char    *name;
    size_t         name_len;
    int64_t        offset;
    uint32_t       used;
    uint32_t       type;
    uint32_t       record_len;
    uint16_t       kind;

    memset(&member, 0, sizeof member);
    type = read_u32(field + 4);
    used = skip_numeric(field, len, 8, &offset);
    if (!used || !pdb_name(field + used, len - used, &name, &name_len))
        return;
    if (record_of(&reader->types, type, &kind, &data, &record_len) && kind == LF_BITFIELD &&
        record_len >= 6) {
        member.bit_size = data[4];
        member.bit_offset = data[5];
        type = read_u32(data);
    }
    member.name = symbuild_string(&reader->builder, name, name_len);
    member.type = convert(reader, type, 0);
    member.offset = (uint64_t)offset;
    symbuild_member(&reader->builder, &member);
}

static void add_enumerator(pdb_reader *reader, const uint8_t *field, uint32_t len)
{
    build_enum  value;
    const char *name;
    size_t      name_len;
    uint32_t    used;

    used = skip_numeric(field, len, 4, &value.value);
    if (!used || !pdb_name(field + used, len - used, &name, &name_len))
        return;
    value.name = symbuild_string(&reader->builder, name, name_len);
    symbuild_enum(&reader->builder, &value);
}

static void walk_fields(pdb_reader *reader, uint32_t field_list, bool enumerators)
{
    const uint8_t *data;
    uint32_t       len;
    uint32_t       offset;
    uint32_t       end;
    uint32_t       chain;
    uint32_t       next;
    uint16_t       kind;
    uint16_t       leaf;

    for (chain = 0; chain < FIELD_LIST_CHAIN && field_list; chain++) {
        if (!record_of(&reader->types, field_list, &kind, &data, &len) || kind != LF_FIELDLIST)
            return;
        next = 0;
        offset = 0;
        while (reader->builder.status == DBG_OK && next_field(data, len, &offset)) {
            leaf = read_u16(data + offset);
            end = field_end(data, len, offset);
            if (!end)
                break;
            if (leaf == LF_MEMBER && !enumerators)
                add_member(reader, data + offset, end - offset);
            else if (leaf == LF_ENUMERATE && enumerators)
                add_enumerator(reader, data + offset, end - offset);
            else if (leaf == LF_INDEX)
                next = read_u32(data + offset + 4);
            offset = end;
        }
        field_list = next;
    }
}

static uint32_t reserve(pdb_reader *reader, uint32_t index, const aggregate *agg, int depth)
{
    build_type type;
    uint32_t   definition;
    uint32_t   result;

    memset(&type, 0, sizeof type);
    type.kind = agg->kind;
    type.name = type_string(reader, agg->name, agg->name_len);
    if (agg->property & PROP_FWDREF) {
        definition = find_definition(reader, agg);
        if (definition && definition != index) {
            result = convert(reader, definition, depth + 1);
            if (result)
                return result;
        }
        type.flags = SYM_TYPE_FORWARD;
        return symbuild_type(&reader->builder, &type);
    }
    if (agg->kind == SYM_TYPE_ENUM) {
        type.target = convert(reader, agg->underlying, depth + 1);
        type.size = type.target ? built(reader, type.target)->size : 4;
        type.first_member = reader->builder.enum_count;
        walk_fields(reader, agg->field, true);
        type.member_count = reader->builder.enum_count - type.first_member;
        return symbuild_type(&reader->builder, &type);
    }
    type.size = (uint32_t)agg->size;
    result = symbuild_type(&reader->builder, &type);
    if (result)
        queue_pending(reader, index);
    return result;
}

static uint32_t modified(pdb_reader *reader, const uint8_t *data, uint32_t len, int depth)
{
    build_type type;
    uint32_t   target;
    uint16_t   modifiers;

    if (len < 6)
        return 0;
    target = convert(reader, read_u32(data), depth + 1);
    modifiers = read_u16(data + 4);
    if (!target)
        return 0;
    type = *built(reader, target);
    if (type.kind == SYM_TYPE_STRUCT || type.kind == SYM_TYPE_UNION ||
        type.kind == SYM_TYPE_ENUM || type.kind == SYM_TYPE_NONE)
        return target;
    if (modifiers & MODIFIER_CONST)
        type.flags |= SYM_TYPE_CONST;
    if (modifiers & MODIFIER_VOLATILE)
        type.flags |= SYM_TYPE_VOLATILE;
    return symbuild_type(&reader->builder, &type);
}

static uint32_t pointer(pdb_reader *reader, const uint8_t *data, uint32_t len, int depth)
{
    build_type type;
    uint32_t   attributes;

    if (len < 8)
        return 0;
    memset(&type, 0, sizeof type);
    attributes = read_u32(data + 4);
    type.kind = SYM_TYPE_POINTER;
    type.size = (attributes >> 13) & 0x3f;
    if (!type.size)
        type.size = reader->machine == PDB_MACHINE_X86 ? 4 : 8;
    if (attributes & POINTER_CONST)
        type.flags |= SYM_TYPE_CONST;
    if (attributes & POINTER_VOLATILE)
        type.flags |= SYM_TYPE_VOLATILE;
    type.target = convert(reader, read_u32(data), depth + 1);
    return symbuild_type(&reader->builder, &type);
}

static uint32_t array(pdb_reader *reader, const uint8_t *data, uint32_t len, int depth)
{
    build_type type;
    int64_t    bytes;
    uint32_t   element_size;

    if (len < 8 || !pdb_numeric(data + 8, len - 8, &bytes))
        return 0;
    memset(&type, 0, sizeof type);
    type.kind = SYM_TYPE_ARRAY;
    type.target = convert(reader, read_u32(data), depth + 1);
    type.size = (uint32_t)bytes;
    element_size = type.target ? built(reader, type.target)->size : 0;
    type.count = element_size ? type.size / element_size : 0;
    return symbuild_type(&reader->builder, &type);
}

static uint32_t function(pdb_reader *reader, const uint8_t *data, uint32_t len, int depth)
{
    build_type type;

    if (len < 4)
        return 0;
    memset(&type, 0, sizeof type);
    type.kind = SYM_TYPE_FUNCTION;
    type.target = convert(reader, read_u32(data), depth + 1);
    return symbuild_type(&reader->builder, &type);
}

static uint32_t convert(pdb_reader *reader, uint32_t index, int depth)
{
    pdb_types     *types;
    const uint8_t *data;
    aggregate      agg;
    uint32_t       len;
    uint32_t       result;
    uint16_t       kind;

    types = &reader->types;
    if (reader->builder.status != DBG_OK)
        return 0;
    if (index < TYPE_FIRST)
        return simple(reader, index);
    if (!record_of(types, index, &kind, &data, &len))
        return 0;
    if (types->map[index - types->first])
        return types->map[index - types->first];
    if (depth > TYPE_DEPTH)
        return 0;
    switch (kind) {
        case LF_MODIFIER:
            result = modified(reader, data, len, depth);
            break;
        case LF_POINTER:
            result = pointer(reader, data, len, depth);
            break;
        case LF_ARRAY:
            result = array(reader, data, len, depth);
            break;
        case LF_PROCEDURE:
        case LF_MFUNCTION:
            result = function(reader, data, len, depth);
            break;
        case LF_BITFIELD:
            result = len >= 4 ? convert(reader, read_u32(data), depth + 1) : 0;
            break;
        default:
            result = read_aggregate(kind, data, len, &agg) ? reserve(reader, index, &agg, depth)
                                                          : 0;
            break;
    }
    types->map[index - types->first] = result;
    return result;
}

uint32_t pdb_type(pdb_reader *reader, uint32_t index)
{
    if (!reader->types.map && index >= TYPE_FIRST)
        return 0;
    return convert(reader, index, 0);
}

static void complete(pdb_reader *reader, uint32_t index)
{
    build_type     *type;
    const uint8_t  *data;
    aggregate       agg;
    uint32_t        built_index;
    uint32_t        first;
    uint32_t        len;
    uint16_t        kind;

    built_index = reader->types.map[index - reader->types.first];
    if (!built_index || !record_of(&reader->types, index, &kind, &data, &len) ||
        !read_aggregate(kind, data, len, &agg))
        return;
    first = reader->builder.member_count;
    walk_fields(reader, agg.field, false);
    if (reader->builder.status != DBG_OK)
        return;
    type = &reader->builder.types[built_index];
    type->first_member = first;
    type->member_count = reader->builder.member_count - first;
}

void pdb_types_finish(pdb_reader *reader)
{
    pdb_types *types;
    uint32_t   done;

    types = &reader->types;
    for (done = 0; done < types->pending_count && reader->builder.status == DBG_OK; done++)
        complete(reader, types->pending[done]);
    types->pending_count = 0;
}

dbg_status pdb_types_open(pdb_reader *reader)
{
    pdb_types *types;
    uint32_t   header_size;
    uint32_t   record_bytes;
    uint32_t   offset;
    uint32_t   end;
    uint32_t   slot;
    uint16_t   length;
    dbg_status status;

    types = &reader->types;
    types->simple = calloc(TYPE_FIRST, sizeof *types->simple);
    if (!types->simple)
        return DBG_E_NOMEM;
    if (reader->msf.stream_count <= PDB_STREAM_TPI)
        return DBG_OK;
    status = pdb_stream_read(reader, PDB_STREAM_TPI, &types->stream);
    if (status != DBG_OK)
        return status;
    if (types->stream.size < TPI_HEADER_MIN)
        return DBG_OK;
    header_size = read_u32(types->stream.data + 4);
    types->first = read_u32(types->stream.data + 8);
    end = read_u32(types->stream.data + 12);
    record_bytes = read_u32(types->stream.data + 16);
    if (types->first < TYPE_FIRST || end < types->first || header_size < TPI_HEADER_MIN ||
        header_size > types->stream.size || record_bytes > types->stream.size - header_size)
        return DBG_OK;
    types->count = end - types->first;
    types->offsets = malloc((types->count ? types->count : 1) * sizeof *types->offsets);
    types->map = calloc(types->count ? types->count : 1, sizeof *types->map);
    if (!types->offsets || !types->map)
        return DBG_E_NOMEM;
    memset(types->offsets, 0xff, (types->count ? types->count : 1) * sizeof *types->offsets);
    offset = header_size;
    end = header_size + record_bytes;
    for (slot = 0; slot < types->count && offset + 4 <= end; slot++) {
        length = read_u16(types->stream.data + offset);
        if (length < 2 || length > end - offset - 2)
            break;
        types->offsets[slot] = offset;
        offset += length + 2u;
    }
    return DBG_OK;
}

void pdb_types_close(pdb_reader *reader)
{
    pdb_types *types;

    types = &reader->types;
    free(types->stream.data);
    free(types->offsets);
    free(types->map);
    free(types->simple);
    free(types->names);
    free(types->pending);
    memset(types, 0, sizeof *types);
}
