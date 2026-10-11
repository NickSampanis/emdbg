#include "image.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define PE_SECTION_SIZE       40u
#define PE_SCN_CNT_CODE       0x00000020u
#define PE_SCN_MEM_EXECUTE    0x20000000u
#define PE_DIR_BASERELOC      5u
#define PE_RELOC_ABSOLUTE     0u
#define PE_RELOC_HIGH         1u
#define PE_RELOC_LOW          2u
#define PE_RELOC_DIR64        10u
#define PE_RELOC_MAX_WIDTH    8u
#define MATCH_MIN_BYTES       8u
#define PE_DIR_DEBUG          6u
#define PE_DIR_EXCEPTION      3u
#define PE_DEBUG_ENTRY_SIZE   28u
#define PE_DEBUG_CODEVIEW     2u
#define TE_HEADER_SIZE        40u
#define TE_MAX_SECTIONS       32u
#define ELF_MAGIC             "\x7f" "ELF"
#define ELF_ET_EXEC           2u
#define ELF_ET_DYN            3u
#define ELF_PT_LOAD           1u
#define ELF_PT_NOTE           4u
#define ELF_NT_GNU_BUILD_ID   3u
#define FNV_OFFSET            0xcbf29ce484222325ull
#define FNV_PRIME             0x100000001b3ull
#define PATTERN_MIN_DISTINCT  8u
#define PATTERN_MIN_DISTANCE  64u
#define PATTERN_STEP          4u
#define PATTERN_SPAN          (64u + IMAGE_PATTERN_SIZE)
#define SECTION_STEP          256u

typedef struct pe_section {
    uint32_t rva;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t flags;
} pe_section;

typedef struct pe_image {
    const uint8_t *data;
    size_t         size;
    pe_section    *sections;
    uint32_t       section_count;
    uint32_t       section_alignment;
    uint32_t       header_size;
    uint32_t       entry_rva;
    uint32_t       reloc_rva;
    uint32_t       reloc_size;
    uint32_t      *relocs;
    uint32_t       reloc_count;
} pe_image;

typedef void (*reloc_fn)(void *user, uint32_t rva, uint32_t width);

typedef struct reloc_mask {
    const pe_image *image;
    uint8_t        *relocated;
} reloc_mask;

typedef struct compiled_pattern {
    const byte_pattern *pattern;
    uint32_t            anchor;
    uint32_t            min_compared;
} compiled_pattern;

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)(bytes[0] | bytes[1] << 8);
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

static int compare_u32(const void *left, const void *right)
{
    uint32_t left_value;
    uint32_t right_value;

    left_value = *(const uint32_t *)left;
    right_value = *(const uint32_t *)right;
    if (left_value == right_value)
        return 0;
    return left_value < right_value ? -1 : 1;
}

static const pe_section *section_of(const pe_image *image, uint32_t rva, uint32_t len)
{
    const pe_section *section;
    uint32_t          index;

    for (index = 0; index < image->section_count; index++) {
        section = &image->sections[index];
        if (rva >= section->rva && rva - section->rva <= section->raw_size &&
            len <= section->raw_size - (rva - section->rva))
            return section;
    }
    return NULL;
}

static const uint8_t *bytes_at(const pe_image *image, const pe_section *section, uint32_t rva)
{
    return image->data + section->raw_offset + (rva - section->rva);
}

static dbg_status pe_parse(pe_image *image)
{
    const uint8_t *optional;
    const uint8_t *section;
    size_t         pe_offset;
    size_t         optional_offset;
    size_t         section_offset;
    uint32_t       optional_size;
    uint32_t       dir_count_offset;
    uint32_t       dir_offset;
    uint32_t       virtual_size;
    uint32_t       index;
    uint16_t       magic;
    pe_section    *entry;

    if (image->size < 0x40 || memcmp(image->data, "MZ", 2))
        return DBG_E_BADARG;
    pe_offset = read_u32(image->data + 0x3c);
    if (pe_offset > image->size - 24 || memcmp(image->data + pe_offset, "PE\0\0", 4))
        return DBG_E_BADARG;
    image->section_count = read_u16(image->data + pe_offset + 6);
    optional_size = read_u16(image->data + pe_offset + 20);
    optional_offset = pe_offset + 24;
    section_offset = optional_offset + optional_size;
    if (optional_size < 96 || section_offset > image->size ||
        (size_t)image->section_count * PE_SECTION_SIZE > image->size - section_offset)
        return DBG_E_BADARG;

    optional = image->data + optional_offset;
    magic = read_u16(optional);
    if (magic == 0x10b) {
        dir_count_offset = 92;
        dir_offset = 96;
    } else if (magic == 0x20b) {
        dir_count_offset = 108;
        dir_offset = 112;
    } else {
        return DBG_E_BADARG;
    }
    image->entry_rva = read_u32(optional + 16);
    image->section_alignment = read_u32(optional + 32);
    image->header_size = read_u32(optional + 60);
    if (optional_size >= dir_offset + (PE_DIR_BASERELOC + 1) * 8 &&
        read_u32(optional + dir_count_offset) > PE_DIR_BASERELOC) {
        image->reloc_rva = read_u32(optional + dir_offset + PE_DIR_BASERELOC * 8);
        image->reloc_size = read_u32(optional + dir_offset + PE_DIR_BASERELOC * 8 + 4);
    }

    image->sections = calloc(image->section_count ? image->section_count : 1,
                             sizeof *image->sections);
    if (!image->sections)
        return DBG_E_NOMEM;
    for (index = 0; index < image->section_count; index++) {
        section = image->data + section_offset + index * PE_SECTION_SIZE;
        entry = &image->sections[index];
        virtual_size = read_u32(section + 8);
        entry->rva = read_u32(section + 12);
        entry->raw_size = read_u32(section + 16);
        entry->raw_offset = read_u32(section + 20);
        entry->flags = read_u32(section + 36);
        if (virtual_size && virtual_size < entry->raw_size)
            entry->raw_size = virtual_size;
        if (entry->raw_offset > image->size)
            entry->raw_size = 0;
        else if (entry->raw_size > image->size - entry->raw_offset)
            entry->raw_size = (uint32_t)(image->size - entry->raw_offset);
    }
    return DBG_OK;
}

static uint32_t reloc_width(uint16_t type)
{
    switch (type) {
        case PE_RELOC_HIGH:
        case PE_RELOC_LOW:
            return 2;
        case PE_RELOC_DIR64:
            return 8;
        default:
            return 4;
    }
}

static void pe_walk_relocs(const pe_image *image, reloc_fn fn, void *user)
{
    const pe_section *section;
    const uint8_t    *block;
    const uint8_t    *table_end;
    uint32_t          page;
    uint32_t          block_size;
    uint32_t          entry_index;
    uint16_t          entry;

    if (!image->reloc_size)
        return;
    section = section_of(image, image->reloc_rva, image->reloc_size);
    if (!section)
        return;
    block = bytes_at(image, section, image->reloc_rva);
    table_end = block + image->reloc_size;
    while ((size_t)(table_end - block) >= 8) {
        page = read_u32(block);
        block_size = read_u32(block + 4);
        if (block_size < 8 || block_size > (size_t)(table_end - block))
            break;
        for (entry_index = 0; entry_index < (block_size - 8) / 2; entry_index++) {
            entry = read_u16(block + 8 + entry_index * 2);
            if (entry >> 12 != PE_RELOC_ABSOLUTE)
                fn(user, page + (entry & 0xfffu), reloc_width((uint16_t)(entry >> 12)));
        }
        block += block_size;
    }
}

static void collect_reloc(void *user, uint32_t rva, uint32_t width)
{
    pe_image *image;

    (void)width;
    image = user;
    image->relocs[image->reloc_count++] = rva;
}

static dbg_status pe_load_relocs(pe_image *image)
{
    if (!image->reloc_size || !section_of(image, image->reloc_rva, image->reloc_size))
        return DBG_OK;
    image->relocs = malloc((image->reloc_size / 2 + 1) * sizeof *image->relocs);
    if (!image->relocs)
        return DBG_E_NOMEM;
    pe_walk_relocs(image, collect_reloc, image);
    qsort(image->relocs, image->reloc_count, sizeof *image->relocs, compare_u32);
    return DBG_OK;
}

static void mark_reloc(void *user, uint32_t rva, uint32_t width)
{
    reloc_mask       *mask;
    const pe_section *section;
    uint32_t          index;

    mask = user;
    for (index = 0; index < width; index++) {
        section = section_of(mask->image, rva + index, 1);
        if (section)
            mask->relocated[section->raw_offset + (rva + index - section->rva)] = 1;
    }
}

static bool is_wildcard(const byte_pattern *pattern, uint32_t index)
{
    return pattern->wildcard && pattern->wildcard[index];
}

static void compile_pattern(const byte_pattern *pattern, compiled_pattern *compiled)
{
    uint32_t index;
    uint32_t usable;
    uint32_t run_start;
    uint32_t run_len;
    uint32_t best_len;

    usable = 0;
    run_start = 0;
    run_len = 0;
    best_len = 0;
    compiled->pattern = pattern;
    compiled->anchor = 0;
    for (index = 0; index < pattern->len; index++) {
        if (is_wildcard(pattern, index)) {
            run_len = 0;
            continue;
        }
        usable++;
        if (!run_len)
            run_start = index;
        run_len++;
        if (run_len > best_len) {
            best_len = run_len;
            compiled->anchor = run_start;
        }
    }
    compiled->min_compared = usable < MATCH_MIN_BYTES ? usable
                           : usable / 2 > MATCH_MIN_BYTES ? usable / 2 : MATCH_MIN_BYTES;
}

static int match_region(const uint8_t *data, const uint8_t *relocated, const pe_section *region,
                        const compiled_pattern *compiled, uint32_t alignment,
                        image_match *matches, int count, int max)
{
    const byte_pattern *pattern;
    size_t              position;
    size_t              last;
    uint32_t            index;
    uint32_t            compared;
    uint32_t            anchor;

    pattern = compiled->pattern;
    anchor = compiled->anchor;
    if (region->raw_size < pattern->len)
        return count;
    last = (size_t)region->raw_offset + region->raw_size - pattern->len;
    for (position = region->raw_offset; position <= last && count < max; position++) {
        if (!(relocated && relocated[position + anchor]) &&
            data[position + anchor] != pattern->bytes[anchor])
            continue;
        compared = 0;
        for (index = 0; index < pattern->len; index++) {
            if (is_wildcard(pattern, index) || (relocated && relocated[position + index]))
                continue;
            if (data[position + index] != pattern->bytes[index])
                break;
            compared++;
        }
        if (index < pattern->len || compared < compiled->min_compared)
            continue;
        matches[count].offset = position;
        matches[count].rva = region->rva + (uint32_t)(position - region->raw_offset);
        matches[count].alignment = alignment;
        count++;
    }
    return count;
}

int image_match_bytes(const uint8_t *data, size_t size, const byte_pattern *pattern,
                      image_match *matches, int max)
{
    compiled_pattern compiled;
    pe_image         image;
    pe_section       region;
    reloc_mask       mask;
    uint32_t         index;
    int              count;
    dbg_status       status;

    count = 0;
    memset(&image, 0, sizeof image);
    memset(&region, 0, sizeof region);
    compile_pattern(pattern, &compiled);
    if (!compiled.min_compared)
        return 0;
    image.data = data;
    image.size = size;
    status = pe_parse(&image);
    if (status == DBG_E_NOMEM)
        return -1;
    if (status != DBG_OK) {
        free(image.sections);
        region.raw_size = size > UINT32_MAX ? UINT32_MAX : (uint32_t)size;
        return match_region(data, NULL, &region, &compiled, 0, matches, 0, max);
    }

    mask.image = &image;
    mask.relocated = calloc(size ? size : 1, 1);
    if (!mask.relocated) {
        free(image.sections);
        return -1;
    }
    pe_walk_relocs(&image, mark_reloc, &mask);
    region.raw_size = image.header_size < size ? image.header_size : (uint32_t)size;
    count = match_region(data, mask.relocated, &region, &compiled, image.section_alignment,
                         matches, count, max);
    for (index = 0; index < image.section_count; index++)
        count = match_region(data, mask.relocated, &image.sections[index], &compiled,
                             image.section_alignment, matches, count, max);
    free(mask.relocated);
    free(image.sections);
    return count;
}

static bool touches_reloc(const pe_image *image, uint32_t rva)
{
    uint32_t first;
    uint32_t low;
    uint32_t high;
    uint32_t middle;

    first = rva >= PE_RELOC_MAX_WIDTH - 1 ? rva - (PE_RELOC_MAX_WIDTH - 1) : 0;
    low = 0;
    high = image->reloc_count;
    while (low < high) {
        middle = low + (high - low) / 2;
        if (image->relocs[middle] < first)
            low = middle + 1;
        else
            high = middle;
    }
    return low < image->reloc_count && image->relocs[low] < rva + IMAGE_PATTERN_SIZE;
}

static bool varied(const uint8_t *bytes)
{
    bool     seen[256];
    uint32_t distinct;
    uint32_t index;

    distinct = 0;
    memset(seen, 0, sizeof seen);
    for (index = 0; index < IMAGE_PATTERN_SIZE; index++) {
        if (!seen[bytes[index]])
            distinct++;
        seen[bytes[index]] = true;
    }
    return distinct >= PATTERN_MIN_DISTINCT;
}

static bool unique_in_image(const pe_image *image, const uint8_t *bytes)
{
    size_t position;
    int    count;

    count = 0;
    for (position = 0; position + IMAGE_PATTERN_SIZE <= image->size; position++) {
        if (image->data[position] != bytes[0] ||
            memcmp(image->data + position, bytes, IMAGE_PATTERN_SIZE))
            continue;
        count++;
        if (count > 1)
            return false;
    }
    return count == 1;
}

static bool try_span(const pe_image *image, uint32_t rva, uint64_t span, image_pattern *pattern)
{
    const pe_section *section;
    const uint8_t    *bytes;
    uint32_t          offset;

    if (span > PATTERN_SPAN)
        span = PATTERN_SPAN;
    for (offset = 0; offset + IMAGE_PATTERN_SIZE <= span; offset += PATTERN_STEP) {
        section = section_of(image, rva + offset, IMAGE_PATTERN_SIZE);
        if (!section || !(section->flags & (PE_SCN_CNT_CODE | PE_SCN_MEM_EXECUTE)))
            continue;
        if (touches_reloc(image, rva + offset))
            continue;
        bytes = bytes_at(image, section, rva + offset);
        if (!varied(bytes) || !unique_in_image(image, bytes))
            continue;
        pattern->rva = rva + offset;
        memcpy(pattern->bytes, bytes, IMAGE_PATTERN_SIZE);
        return true;
    }
    return false;
}

static void add_candidate(const pe_image *image, uint64_t rva, uint64_t span,
                          image_pattern *patterns, int *found)
{
    image_pattern candidate;
    uint32_t      distance;

    if (*found >= 2 || rva > UINT32_MAX - PATTERN_SPAN)
        return;
    if (!try_span(image, (uint32_t)rva, span, &candidate))
        return;
    if (*found == 1) {
        distance = candidate.rva > patterns[0].rva ? candidate.rva - patterns[0].rva
                                                   : patterns[0].rva - candidate.rva;
        if (distance < PATTERN_MIN_DISTANCE)
            return;
    }
    patterns[(*found)++] = candidate;
}

dbg_status image_find_patterns(dbg_ctx *dbg, const char *path, const uint8_t *data, size_t size,
                               const sym_module *module, image_pattern *patterns)
{
    const pe_section *section;
    pe_image          image;
    uint32_t          index;
    uint32_t          offset;
    int               found;
    dbg_status        status;

    found = 0;
    memset(&image, 0, sizeof image);
    image.data = data;
    image.size = size;
    status = pe_parse(&image);
    if (status == DBG_OK)
        status = pe_load_relocs(&image);
    if (status == DBG_E_BADARG)
        dbg_out(dbg, DBG_OUT_ERROR, "%s: not a PE image\n", path);
    if (status != DBG_OK) {
        free(image.sections);
        free(image.relocs);
        return status;
    }

    add_candidate(&image, image.entry_rva, PATTERN_SPAN, patterns, &found);
    for (index = 0; index < module->pub.function_count && found < 2; index++)
        add_candidate(&image, module->funcs[index].start,
                      module->funcs[index].end - module->funcs[index].start, patterns, &found);
    for (index = 0; index < image.section_count && found < 2; index++) {
        section = &image.sections[index];
        if (!(section->flags & (PE_SCN_CNT_CODE | PE_SCN_MEM_EXECUTE)))
            continue;
        for (offset = 0; offset + PATTERN_SPAN <= section->raw_size && found < 2;
             offset += SECTION_STEP)
            add_candidate(&image, (uint64_t)section->rva + offset, PATTERN_SPAN, patterns,
                          &found);
    }
    free(image.sections);
    free(image.relocs);
    if (found < 2) {
        dbg_out(dbg, DBG_OUT_ERROR, "%s: no two unique relocation-free code patterns found\n",
                path);
        return DBG_E_BADARG;
    }
    return DBG_OK;
}

static uint64_t read_u64(const uint8_t *bytes)
{
    return (uint64_t)read_u32(bytes) | (uint64_t)read_u32(bytes + 4) << 32;
}

static uint64_t fnv_hash(uint64_t hash, const uint8_t *bytes, size_t len)
{
    size_t index;

    for (index = 0; index < len; index++) {
        hash ^= bytes[index];
        hash *= FNV_PRIME;
    }
    return hash;
}

static bool parse_pe_header(const uint8_t *data, size_t size, image_header *header)
{
    const uint8_t *optional;
    size_t         pe_offset;
    size_t         optional_offset;
    size_t         section_offset;
    uint32_t       optional_size;
    uint32_t       section_count;
    uint32_t       dir_count_offset;
    uint32_t       dir_offset;
    uint16_t       magic;

    if (size < 0x40 || memcmp(data, "MZ", 2))
        return false;
    pe_offset = read_u32(data + 0x3c);
    if (pe_offset > size - 24 || memcmp(data + pe_offset, "PE\0\0", 4))
        return false;
    section_count = read_u16(data + pe_offset + 6);
    optional_size = read_u16(data + pe_offset + 20);
    optional_offset = pe_offset + 24;
    section_offset = optional_offset + optional_size;
    if (optional_size < 96 || section_offset > size ||
        (size_t)section_count * PE_SECTION_SIZE > size - section_offset)
        return false;
    optional = data + optional_offset;
    magic = read_u16(optional);
    if (magic == 0x10b) {
        dir_count_offset = 92;
        dir_offset = 96;
    } else if (magic == 0x20b) {
        dir_count_offset = 108;
        dir_offset = 112;
    } else {
        return false;
    }
    header->format = DBG_IMAGE_PE;
    header->size = read_u32(optional + 56);
    if (optional_size >= dir_offset + (PE_DIR_DEBUG + 1) * 8 &&
        read_u32(optional + dir_count_offset) > PE_DIR_DEBUG) {
        header->debug_rva = read_u32(optional + dir_offset + PE_DIR_DEBUG * 8);
        header->debug_size = read_u32(optional + dir_offset + PE_DIR_DEBUG * 8 + 4);
    }
    if (optional_size >= dir_offset + (PE_DIR_EXCEPTION + 1) * 8 &&
        read_u32(optional + dir_count_offset) > PE_DIR_EXCEPTION) {
        header->exception_rva = read_u32(optional + dir_offset + PE_DIR_EXCEPTION * 8);
        header->exception_size = read_u32(optional + dir_offset + PE_DIR_EXCEPTION * 8 + 4);
    }
    header->fingerprint = fnv_hash(FNV_OFFSET, optional + 16, 4);
    header->fingerprint = fnv_hash(header->fingerprint, data + section_offset,
                                   (size_t)section_count * PE_SECTION_SIZE);
    return header->size != 0;
}

static bool parse_te_header(const uint8_t *data, size_t size, image_header *header)
{
    const uint8_t *section;
    uint32_t       section_count;
    uint32_t       stripped;
    uint32_t       index;
    uint64_t       end;

    if (size < TE_HEADER_SIZE || memcmp(data, "VZ", 2))
        return false;
    section_count = data[4];
    stripped = read_u16(data + 6);
    if (section_count == 0 || section_count > TE_MAX_SECTIONS || stripped < TE_HEADER_SIZE ||
        TE_HEADER_SIZE + section_count * PE_SECTION_SIZE > size)
        return false;
    header->format = DBG_IMAGE_TE;
    header->base_delta = stripped - TE_HEADER_SIZE;
    for (index = 0; index < section_count; index++) {
        section = data + TE_HEADER_SIZE + index * PE_SECTION_SIZE;
        end = (uint64_t)read_u32(section + 12) + read_u32(section + 8);
        if (end > header->size)
            header->size = end;
    }
    header->debug_rva = read_u32(data + 32);
    header->debug_size = read_u32(data + 36);
    header->fingerprint = fnv_hash(FNV_OFFSET, data + 8, 4);
    header->fingerprint = fnv_hash(header->fingerprint, data + TE_HEADER_SIZE,
                                   section_count * PE_SECTION_SIZE);
    return header->size > header->base_delta;
}

static bool parse_elf_header(const uint8_t *data, size_t size, image_header *header)
{
    const uint8_t *program;
    uint64_t       program_offset;
    uint64_t       first_vaddr;
    uint64_t       first_offset;
    uint64_t       end;
    uint64_t       vaddr;
    uint64_t       offset;
    uint64_t       file_size;
    uint64_t       memory_size;
    uint32_t       entry_size;
    uint32_t       min_entry;
    uint32_t       count;
    uint32_t       header_size;
    uint32_t       type;
    uint32_t       index;
    bool           wide;

    if (size < 52 || memcmp(data, ELF_MAGIC, 4) || data[5] != 1)
        return false;
    if (data[4] != 1 && data[4] != 2)
        return false;
    wide = data[4] == 2;
    type = read_u16(data + 16);
    if (type != ELF_ET_EXEC && type != ELF_ET_DYN)
        return false;
    if (wide && size < 64)
        return false;
    program_offset = wide ? read_u64(data + 32) : read_u32(data + 28);
    header_size = read_u16(data + (wide ? 52 : 40));
    entry_size = read_u16(data + (wide ? 54 : 42));
    count = read_u16(data + (wide ? 56 : 44));
    min_entry = wide ? 56 : 32;
    if (entry_size < min_entry || count == 0 || header_size > size || program_offset > size ||
        (uint64_t)count * entry_size > size - program_offset)
        return false;

    first_vaddr = UINT64_MAX;
    first_offset = UINT64_MAX;
    end = 0;
    for (index = 0; index < count; index++) {
        program = data + program_offset + (size_t)index * entry_size;
        type = read_u32(program);
        offset = wide ? read_u64(program + 8) : read_u32(program + 4);
        vaddr = wide ? read_u64(program + 16) : read_u32(program + 8);
        file_size = wide ? read_u64(program + 32) : read_u32(program + 16);
        memory_size = wide ? read_u64(program + 40) : read_u32(program + 20);
        if (type == ELF_PT_LOAD) {
            if (vaddr < first_vaddr) {
                first_vaddr = vaddr;
                first_offset = offset;
            }
            if (vaddr + memory_size > end)
                end = vaddr + memory_size;
        } else if (type == ELF_PT_NOTE && header->note_count < IMAGE_MAX_NOTES) {
            header->note_vaddr[header->note_count] = vaddr;
            header->note_size[header->note_count] = file_size;
            header->note_count++;
        }
    }
    if (first_vaddr == UINT64_MAX || first_offset != 0 || end <= first_vaddr)
        return false;
    for (index = 0; index < header->note_count; index++)
        header->note_vaddr[index] -= first_vaddr;
    header->format = DBG_IMAGE_ELF;
    header->size = end - first_vaddr;
    header->fingerprint = fnv_hash(FNV_OFFSET, data, header_size);
    header->fingerprint = fnv_hash(header->fingerprint, data + program_offset,
                                   (size_t)count * entry_size);
    return true;
}

bool image_parse_header(const uint8_t *data, size_t size, image_header *header)
{
    memset(header, 0, sizeof *header);
    if (parse_pe_header(data, size, header))
        return true;
    memset(header, 0, sizeof *header);
    if (parse_te_header(data, size, header))
        return true;
    memset(header, 0, sizeof *header);
    if (parse_elf_header(data, size, header))
        return true;
    memset(header, 0, sizeof *header);
    return false;
}

static size_t align4(size_t value)
{
    return (value + 3) & ~(size_t)3;
}

bool image_build_id(const uint8_t *notes, size_t size, uint8_t *id, uint32_t cap,
                    uint32_t *id_len)
{
    size_t   position;
    size_t   name_at;
    size_t   desc_at;
    size_t   next;
    uint32_t name_size;
    uint32_t desc_size;
    uint32_t type;

    position = 0;
    while (position + 12 <= size) {
        name_size = read_u32(notes + position);
        desc_size = read_u32(notes + position + 4);
        type = read_u32(notes + position + 8);
        name_at = position + 12;
        desc_at = name_at + align4(name_size);
        next = desc_at + align4(desc_size);
        if (desc_at > size || next > size || next <= position)
            return false;
        if (type == ELF_NT_GNU_BUILD_ID && name_size == 4 && !memcmp(notes + name_at, "GNU", 4)) {
            *id_len = desc_size < cap ? desc_size : cap;
            memcpy(id, notes + desc_at, *id_len);
            return true;
        }
        position = next;
    }
    return false;
}

bool image_debug_record(const uint8_t *entries, size_t size, uint32_t *record_rva,
                        uint32_t *record_size)
{
    size_t position;

    for (position = 0; position + PE_DEBUG_ENTRY_SIZE <= size; position += PE_DEBUG_ENTRY_SIZE) {
        if (read_u32(entries + position + 12) != PE_DEBUG_CODEVIEW)
            continue;
        *record_size = read_u32(entries + position + 16);
        *record_rva = read_u32(entries + position + 20);
        return *record_rva != 0 && *record_size != 0;
    }
    return false;
}

bool image_codeview_path(const uint8_t *record, size_t size, char *path, size_t cap)
{
    const uint8_t *text;
    const uint8_t *text_end;
    size_t         available;
    size_t         len;

    if (size >= 24 && !memcmp(record, "RSDS", 4))
        text = record + 24;
    else if (size >= 16 && !memcmp(record, "NB10", 4))
        text = record + 16;
    else
        return false;
    available = size - (size_t)(text - record);
    text_end = memchr(text, '\0', available);
    len = text_end ? (size_t)(text_end - text) : available;
    if (!len || !cap)
        return false;
    if (len >= cap)
        len = cap - 1;
    memcpy(path, text, len);
    path[len] = '\0';
    return true;
}
