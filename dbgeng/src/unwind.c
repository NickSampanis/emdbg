#include "dbg.h"
#include "disasm.h"
#include "image.h"

#include <stdlib.h>
#include <string.h>

#define PDATA_ENTRY_SIZE      12u
#define PDATA_MAX_ENTRIES     0x100000u
#define HEADER_READ           0x1000u
#define NO_IMAGE_REGION       0x10000u
#define EPILOG_READ           64u
#define UNWIND_MAX_CHAIN      8
#define UNWIND_HEADER_SIZE    4u
#define UNWIND_FLAG_CHAININFO 0x4u

#define UWOP_PUSH_NONVOL      0u
#define UWOP_ALLOC_LARGE      1u
#define UWOP_ALLOC_SMALL      2u
#define UWOP_SET_FPREG        3u
#define UWOP_SAVE_NONVOL      4u
#define UWOP_SAVE_NONVOL_FAR  5u
#define UWOP_EPILOG           6u
#define UWOP_SAVE_XMM128      8u
#define UWOP_SAVE_XMM128_FAR  9u
#define UWOP_PUSH_MACHFRAME   10u

typedef struct gpr_alias {
    const char *name;
    uint8_t     index;
    uint8_t     shift;
    uint8_t     size;
} gpr_alias;

static const gpr_alias gpr_aliases[] = {
    { "rax", 0, 0, 8 },  { "eax", 0, 0, 4 },  { "ax", 0, 0, 2 },   { "al", 0, 0, 1 },
    { "ah", 0, 8, 1 },   { "rcx", 1, 0, 8 },  { "ecx", 1, 0, 4 },  { "cx", 1, 0, 2 },
    { "cl", 1, 0, 1 },   { "ch", 1, 8, 1 },   { "rdx", 2, 0, 8 },  { "edx", 2, 0, 4 },
    { "dx", 2, 0, 2 },   { "dl", 2, 0, 1 },   { "dh", 2, 8, 1 },   { "rbx", 3, 0, 8 },
    { "ebx", 3, 0, 4 },  { "bx", 3, 0, 2 },   { "bl", 3, 0, 1 },   { "bh", 3, 8, 1 },
    { "rsp", 4, 0, 8 },  { "esp", 4, 0, 4 },  { "sp", 4, 0, 2 },   { "spl", 4, 0, 1 },
    { "rbp", 5, 0, 8 },  { "ebp", 5, 0, 4 },  { "bp", 5, 0, 2 },   { "bpl", 5, 0, 1 },
    { "rsi", 6, 0, 8 },  { "esi", 6, 0, 4 },  { "si", 6, 0, 2 },   { "sil", 6, 0, 1 },
    { "rdi", 7, 0, 8 },  { "edi", 7, 0, 4 },  { "di", 7, 0, 2 },   { "dil", 7, 0, 1 },
    { "r8", 8, 0, 8 },   { "r8d", 8, 0, 4 },  { "r8w", 8, 0, 2 },  { "r8b", 8, 0, 1 },
    { "r9", 9, 0, 8 },   { "r9d", 9, 0, 4 },  { "r9w", 9, 0, 2 },  { "r9b", 9, 0, 1 },
    { "r10", 10, 0, 8 }, { "r10d", 10, 0, 4 }, { "r10w", 10, 0, 2 }, { "r10b", 10, 0, 1 },
    { "r11", 11, 0, 8 }, { "r11d", 11, 0, 4 }, { "r11w", 11, 0, 2 }, { "r11b", 11, 0, 1 },
    { "r12", 12, 0, 8 }, { "r12d", 12, 0, 4 }, { "r12w", 12, 0, 2 }, { "r12b", 12, 0, 1 },
    { "r13", 13, 0, 8 }, { "r13d", 13, 0, 4 }, { "r13w", 13, 0, 2 }, { "r13b", 13, 0, 1 },
    { "r14", 14, 0, 8 }, { "r14d", 14, 0, 4 }, { "r14w", 14, 0, 2 }, { "r14b", 14, 0, 1 },
    { "r15", 15, 0, 8 }, { "r15d", 15, 0, 4 }, { "r15w", 15, 0, 2 }, { "r15b", 15, 0, 1 },
};

int unwind_gpr(const char *name, uint8_t *shift, uint8_t *size)
{
    uint32_t index;

    for (index = 0; index < sizeof gpr_aliases / sizeof gpr_aliases[0]; index++) {
        if (strcmp(gpr_aliases[index].name, name))
            continue;
        *shift = gpr_aliases[index].shift;
        *size = gpr_aliases[index].size;
        return gpr_aliases[index].index;
    }
    return -1;
}

static int gpr_index(const char *name)
{
    uint8_t shift;
    uint8_t size;
    int     index;

    index = unwind_gpr(name, &shift, &size);
    return index >= 0 && size == 8 ? index : -1;
}

static void add_save(unwind_result *out, uint8_t reg, uint8_t base, int64_t offset)
{
    if (out->save_count >= UNWIND_MAX_SAVES)
        return;
    out->saves[out->save_count].reg = reg;
    out->saves[out->save_count].base = base;
    out->saves[out->save_count].offset = offset;
    out->save_count++;
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

static bool read_target(dbg_ctx *dbg, uint64_t addr, void *buf, uint32_t len)
{
    uint32_t   done;
    dbg_status status;

    done = 0;
    status = dbg_read_mem(dbg, paging_enabled(dbg) ? EM_SPACE_VIRT : EM_SPACE_PHYS, addr, buf,
                          len, &done);
    return done == len && (status == DBG_OK || status == DBG_E_PARTIAL);
}

static bool read_header(dbg_ctx *dbg, uint64_t base, image_header *header)
{
    uint8_t data[HEADER_READ];

    return read_target(dbg, base, data, sizeof data) &&
           image_parse_header(data, sizeof data, header) && header->format == DBG_IMAGE_PE;
}

static void drop_image(dbg_ctx *dbg, uint32_t index)
{
    free(dbg->pdata[index].table);
    memmove(&dbg->pdata[index], &dbg->pdata[index + 1],
            (size_t)(dbg->pdata_count - index - 1) * sizeof *dbg->pdata);
    dbg->pdata_count--;
}

void unwind_forget(dbg_ctx *dbg)
{
    while (dbg->pdata_count)
        drop_image(dbg, dbg->pdata_count - 1);
    free(dbg->pdata);
    dbg->pdata = NULL;
    dbg->no_image_count = 0;
}

static pdata_image *load_image(dbg_ctx *dbg, uint64_t base)
{
    image_header header;
    pdata_image *grown;
    pdata_image *image;
    uint32_t     count;

    if (!read_header(dbg, base, &header))
        return NULL;
    grown = realloc(dbg->pdata, (size_t)(dbg->pdata_count + 1) * sizeof *grown);
    if (!grown)
        return NULL;
    dbg->pdata = grown;
    image = &dbg->pdata[dbg->pdata_count];
    memset(image, 0, sizeof *image);
    image->base = base;
    image->end = base + header.size;
    image->fingerprint = header.fingerprint;
    image->generation = dbg->stop_generation;
    count = header.exception_size / PDATA_ENTRY_SIZE;
    if (count && count <= PDATA_MAX_ENTRIES) {
        image->table = malloc((size_t)count * PDATA_ENTRY_SIZE);
        if (image->table && read_target(dbg, base + header.exception_rva, image->table,
                                        count * PDATA_ENTRY_SIZE))
            image->count = count;
    }
    dbg->pdata_count++;
    return image;
}

static bool known_without_image(dbg_ctx *dbg, uint64_t region)
{
    uint32_t index;

    if (dbg->no_image_generation != dbg->stop_generation) {
        dbg->no_image_generation = dbg->stop_generation;
        dbg->no_image_count = 0;
    }
    for (index = 0; index < dbg->no_image_count; index++)
        if (dbg->no_image[index] == region)
            return true;
    return false;
}

static void remember_no_image(dbg_ctx *dbg, uint64_t region)
{
    if (dbg->no_image_count < UNWIND_NO_IMAGE_SLOTS)
        dbg->no_image[dbg->no_image_count++] = region;
}

static pdata_image *image_for(dbg_ctx *dbg, uint64_t pc)
{
    image_header header;
    sym_module  *module;
    pdata_image *image;
    uint64_t     base;
    uint64_t     region;
    uint32_t     index;

    for (index = 0; index < dbg->pdata_count; index++) {
        image = &dbg->pdata[index];
        if (pc < image->base || pc >= image->end)
            continue;
        if (image->generation == dbg->stop_generation)
            return image;
        if (read_header(dbg, image->base, &header) && header.fingerprint == image->fingerprint) {
            image->generation = dbg->stop_generation;
            return image;
        }
        drop_image(dbg, index);
        break;
    }
    region = pc & ~(uint64_t)(NO_IMAGE_REGION - 1);
    if (known_without_image(dbg, region))
        return NULL;
    module = sym_module_at(dbg, pc);
    base = 0;
    if (module)
        base = module->pub.base;
    else if (!image_locate(dbg, pc, &base))
        base = 0;
    image = base ? load_image(dbg, base) : NULL;
    if (!image || pc >= image->end)
        remember_no_image(dbg, region);
    return image && pc < image->end ? image : NULL;
}

static const uint8_t *find_entry(const pdata_image *image, uint32_t rva)
{
    const uint8_t *entry;
    uint32_t       low;
    uint32_t       high;
    uint32_t       middle;

    low = 0;
    high = image->count;
    while (low < high) {
        middle = low + (high - low) / 2;
        entry = image->table + (size_t)middle * PDATA_ENTRY_SIZE;
        if (rva < read_u32(entry))
            high = middle;
        else if (rva >= read_u32(entry + 4))
            low = middle + 1;
        else
            return entry;
    }
    return NULL;
}

static uint32_t code_slots(uint8_t op, uint8_t info)
{
    switch (op) {
        case UWOP_ALLOC_LARGE:
            return info == 0 ? 2u : 3u;
        case UWOP_SAVE_NONVOL:
        case UWOP_SAVE_XMM128:
        case UWOP_EPILOG:
            return 2u;
        case UWOP_SAVE_NONVOL_FAR:
        case UWOP_SAVE_XMM128_FAR:
            return 3u;
        default:
            return 1u;
    }
}

static uint16_t code_word(const uint8_t *info, uint32_t slot)
{
    return (uint16_t)(info[UNWIND_HEADER_SIZE + slot * 2] |
                      info[UNWIND_HEADER_SIZE + slot * 2 + 1] << 8);
}

static bool frame_pointer_set(const uint8_t *info, uint32_t count, uint32_t prolog_offset)
{
    uint32_t slot;
    uint16_t code;

    code = 0;
    for (slot = 0; slot < count; slot += code_slots((uint8_t)(code >> 8 & 0xf),
                                                     (uint8_t)(code >> 12))) {
        code = code_word(info, slot);
        if ((code >> 8 & 0xf) == UWOP_SET_FPREG && prolog_offset >= (code & 0xff))
            return true;
    }
    return false;
}

static bool apply_codes(dbg_ctx *dbg, const pdata_image *image, uint32_t unwind_rva,
                        uint32_t prolog_offset, unwind_result *out)
{
    uint8_t  info[UNWIND_HEADER_SIZE + 256 * 2 + PDATA_ENTRY_SIZE];
    uint32_t chain;
    uint32_t count;
    uint32_t slot;
    uint32_t used;
    uint16_t code;
    uint8_t  flags;
    uint8_t  frame_reg;
    uint8_t  frame_scaled;
    uint8_t  save_base;
    int64_t  save_offset;
    uint8_t  op;
    uint8_t  op_info;

    op = 0;
    op_info = 0;
    for (chain = 0; chain < UNWIND_MAX_CHAIN; chain++) {
        if (!read_target(dbg, image->base + unwind_rva, info, UNWIND_HEADER_SIZE))
            return false;
        flags = info[0] >> 3;
        count = info[2];
        frame_reg = info[3] & 0xf;
        frame_scaled = info[3] >> 4;
        used = (count + 1) & ~1u;
        if (!read_target(dbg, image->base + unwind_rva, info,
                         UNWIND_HEADER_SIZE + used * 2 +
                         (flags & UNWIND_FLAG_CHAININFO ? PDATA_ENTRY_SIZE : 0)))
            return false;
        save_base = UNWIND_GPR_SP;
        save_offset = 0;
        if (frame_reg && frame_pointer_set(info, count, prolog_offset)) {
            save_base = frame_reg;
            save_offset = -(int64_t)frame_scaled * 16;
        }
        for (slot = 0; slot < count; slot += code_slots(op, op_info)) {
            code = code_word(info, slot);
            op = (uint8_t)(code >> 8 & 0xf);
            op_info = (uint8_t)(code >> 12);
            if (prolog_offset < (code & 0xffu))
                continue;
            if (slot + code_slots(op, op_info) > count)
                return false;
            switch (op) {
                case UWOP_PUSH_NONVOL:
                    add_save(out, op_info, out->base, out->offset);
                    out->offset += 8;
                    break;
                case UWOP_ALLOC_SMALL:
                    out->offset += (int64_t)op_info * 8 + 8;
                    break;
                case UWOP_ALLOC_LARGE:
                    if (op_info == 0)
                        out->offset += (int64_t)code_word(info, slot + 1) * 8;
                    else
                        out->offset += read_u32(&info[UNWIND_HEADER_SIZE + (slot + 1) * 2]);
                    break;
                case UWOP_SET_FPREG:
                    out->base = frame_reg;
                    out->offset = -(int64_t)frame_scaled * 16;
                    break;
                case UWOP_SAVE_NONVOL:
                    add_save(out, op_info, save_base,
                             save_offset + (int64_t)code_word(info, slot + 1) * 8);
                    break;
                case UWOP_SAVE_NONVOL_FAR:
                    add_save(out, op_info, save_base,
                             save_offset + read_u32(&info[UNWIND_HEADER_SIZE + (slot + 1) * 2]));
                    break;
                case UWOP_PUSH_MACHFRAME:
                    return false;
                default:
                    break;
            }
        }
        if (!(flags & UNWIND_FLAG_CHAININFO))
            return true;
        unwind_rva = read_u32(&info[UNWIND_HEADER_SIZE + used * 2 + 8]);
        prolog_offset = UINT32_MAX;
    }
    return false;
}

static bool epilog_rule(const uint8_t *code, uint32_t len, unwind_result *out)
{
    epilog_info epilog;
    uint32_t    index;
    int         base;
    int         reg;

    if (!disasm_epilog(code, len, &epilog))
        return false;
    base = gpr_index(epilog.base);
    if (base < 0)
        return false;
    out->base = (uint8_t)base;
    out->offset = epilog.cfa_offset;
    for (index = 0; index < epilog.pop_count; index++) {
        reg = gpr_index(epilog.pops[index]);
        if (reg >= 0)
            add_save(out, (uint8_t)reg, (uint8_t)base, epilog.pop_offsets[index]);
    }
    return true;
}

bool unwind_rule(dbg_ctx *dbg, uint64_t pc, uint64_t lookup, unwind_result *out)
{
    pdata_image   *image;
    const uint8_t *entry;
    uint8_t        code[EPILOG_READ];
    uint32_t       rva;

    memset(out, 0, sizeof *out);
    out->base = UNWIND_GPR_SP;
    if (dbg->mode != DBG_MODE_LONG64)
        return false;
    image = image_for(dbg, lookup);
    if (!image || !image->count)
        return false;
    if (read_target(dbg, pc, code, sizeof code)) {
        bp_hide(dbg, pc, code, sizeof code);
        if (epilog_rule(code, sizeof code, out))
            return true;
        memset(out, 0, sizeof *out);
        out->base = UNWIND_GPR_SP;
    }
    rva = (uint32_t)(lookup - image->base);
    entry = find_entry(image, rva);
    if (entry && !apply_codes(dbg, image, read_u32(entry + 8), rva - read_u32(entry), out))
        return false;
    out->offset += 8;
    return out->base < UNWIND_GPRS;
}
