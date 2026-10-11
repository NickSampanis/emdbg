#include "dbg.h"
#include "disasm.h"
#include "image.h"
#include "plat.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIND_MAX_LEN       256u
#define FIND_FILE_MATCHES  16
#define FIND_EXTENSION     32
#define FIND_MIN_DISTINCT  4u
#define FIND_GOOD_DISTINCT 8u
#define FIND_MIN_USABLE    16u
#define FIND_SLIDE         0x200u
#define WALK_PAGE          0x1000u
#define WALK_CHUNK         0x10000u
#define WALK_LIMIT         0x1000000u
#define HEADER_READ        0x1000u
#define RECORD_READ        0x400u
#define NOTES_READ         0x1000u
#define DEBUG_ENTRIES_READ (16u * 28u)

typedef struct image_search {
    const image_header *header;
    dbg_image          *out;
    const char         *dir;
} image_search;

typedef struct find_state {
    dbg_ctx            *dbg;
    const char         *dir;
    const char         *extension;
    const byte_pattern *pattern;
    uint64_t            addr;
    dbg_find_match     *matches;
    int                 max;
    int                 count;
    int                 files;
    dbg_status          status;
} find_state;

static void walk_dirs(dbg_ctx *dbg, const char *dirs, char *dir_text, plat_dir_fn fn,
                      void *user)
{
    const char *dir;
    const char *dir_end;
    size_t      dir_len;

    for (dir = dirs; *dir; dir = *dir_end ? dir_end + 1 : dir_end) {
        dir_end = strchr(dir, ';');
        if (!dir_end)
            dir_end = dir + strlen(dir);
        dir_len = (size_t)(dir_end - dir);
        while (dir_len && (dir[dir_len - 1] == '/' || dir[dir_len - 1] == '\\'))
            dir_len--;
        if (!dir_len || dir_len >= DBG_FIND_PATH)
            continue;
        memcpy(dir_text, dir, dir_len);
        dir_text[dir_len] = '\0';
        if (plat_list_dir(dir_text, fn, user) != 0)
            dbg_out(dbg, DBG_OUT_ERROR, "%s: cannot list the folder\n", dir_text);
    }
}

static bool has_extension(const char *name, const char *extension)
{
    size_t name_len;
    size_t extension_len;
    size_t index;

    name_len = strlen(name);
    extension_len = strlen(extension);
    if (name_len <= extension_len)
        return false;
    for (index = 0; index < extension_len; index++)
        if (tolower((unsigned char)name[name_len - extension_len + index]) !=
            tolower((unsigned char)extension[index]))
            return false;
    return true;
}

static void add_match(find_state *state, const char *path, const image_match *found)
{
    dbg_find_match *match;

    state->count++;
    if (state->count > state->max)
        return;
    match = &state->matches[state->count - 1];
    snprintf(match->file, sizeof match->file, "%s", path);
    match->offset = found->offset;
    match->rva = found->rva;
    match->base = state->addr - found->rva;
    match->is_pe = found->alignment != 0;
    match->aligned = !match->is_pe || match->base % found->alignment == 0;
}

static void search_file(void *user, const char *name)
{
    find_state *state;
    image_match found[FIND_FILE_MATCHES];
    char        path[DBG_FIND_PATH];
    uint8_t    *data;
    size_t      size;
    int         hits;
    int         index;

    state = user;
    size = 0;
    if (state->status != DBG_OK || !has_extension(name, state->extension))
        return;
    if (snprintf(path, sizeof path, "%s/%s", state->dir, name) >= (int)sizeof path)
        return;
    data = sym_read_file(path, &size);
    if (!data)
        return;
    state->files++;
    hits = image_match_bytes(data, size, state->pattern, found, FIND_FILE_MATCHES);
    free(data);
    if (hits < 0) {
        state->status = DBG_E_NOMEM;
        return;
    }
    for (index = 0; index < hits; index++)
        add_match(state, path, &found[index]);
}

static uint32_t usable_count(const uint8_t *wildcard, uint32_t len)
{
    uint32_t usable;
    uint32_t index;

    usable = 0;
    for (index = 0; index < len; index++)
        usable += !wildcard[index];
    return usable;
}

static uint32_t distinct_usable(const byte_pattern *pattern)
{
    bool     seen[256];
    uint32_t distinct;
    uint32_t index;

    distinct = 0;
    memset(seen, 0, sizeof seen);
    for (index = 0; index < pattern->len; index++) {
        if (pattern->wildcard[index])
            continue;
        if (!seen[pattern->bytes[index]])
            distinct++;
        seen[pattern->bytes[index]] = true;
    }
    return distinct;
}

static bool good_window(const uint8_t *span, const uint8_t *wildcard, uint32_t len,
                        uint32_t usable)
{
    byte_pattern pattern;

    pattern.bytes = span;
    pattern.wildcard = wildcard;
    pattern.len = len;
    return usable * 4 >= len * 3 && distinct_usable(&pattern) >= FIND_GOOD_DISTINCT;
}

static uint32_t pick_window(const uint8_t *span, const uint8_t *wildcard, const uint8_t *starts,
                            uint32_t span_len, uint32_t len)
{
    byte_pattern pattern;
    uint32_t     offset;
    uint32_t     best;
    uint32_t     best_usable;
    uint32_t     usable;

    best = 0;
    best_usable = usable_count(wildcard, len);
    if (good_window(span, wildcard, len, best_usable))
        return 0;
    for (offset = 1; offset + len <= span_len; offset++) {
        if (!starts[offset])
            continue;
        usable = usable_count(wildcard + offset, len);
        pattern.bytes = span + offset;
        pattern.wildcard = wildcard + offset;
        pattern.len = len;
        if (usable <= best_usable || distinct_usable(&pattern) < FIND_GOOD_DISTINCT)
            continue;
        best = offset;
        best_usable = usable;
        if (good_window(span + offset, wildcard + offset, len, usable))
            break;
    }
    return best;
}

static void normalize_extension(const char *extension, char *out, size_t cap)
{
    while (*extension == '*')
        extension++;
    snprintf(out, cap, "%s%s", *extension == '.' ? "" : ".", extension);
}

dbg_status dbg_find(dbg_ctx *dbg, uint64_t addr, uint32_t len, const char *extension,
                    const char *dirs, dbg_find_match *matches, int max, int *count,
                    int *files_searched)
{
    find_state   state;
    byte_pattern pattern;
    uint8_t      span[FIND_MAX_LEN + FIND_SLIDE];
    uint8_t      wildcard[FIND_MAX_LEN + FIND_SLIDE];
    uint8_t      starts[FIND_MAX_LEN + FIND_SLIDE];
    char         normalized[FIND_EXTENSION];
    char         dir_text[DBG_FIND_PATH];
    uint32_t     done;
    uint32_t     decoded;
    uint32_t     window;
    uint32_t     usable;
    dbg_status   status;

    done = 0;
    *count = 0;
    *files_searched = 0;
    if (dbg->state == DBG_STATE_DISCONNECTED)
        return DBG_E_DISCONNECTED;
    if (len == 0 || len > FIND_MAX_LEN)
        return DBG_E_BADARG;
    if (!dirs || !*dirs)
        dirs = dbg_get_exe_path(dbg);
    if (!*dirs) {
        dbg_out(dbg, DBG_OUT_ERROR, "no folder given and no executable folders set (.exepath)\n");
        return DBG_E_BADARG;
    }
    normalize_extension(extension, normalized, sizeof normalized);
    status = dbg_read_mem(dbg, paging_enabled(dbg) ? EM_SPACE_VIRT : EM_SPACE_PHYS, addr, span,
                          len + FIND_SLIDE, &done);
    if (done < len) {
        dbg_out(dbg, DBG_OUT_ERROR, "cannot read %u bytes at %llx\n", len,
                (unsigned long long)addr);
        return status == DBG_OK ? DBG_E_FAULT : status;
    }

    decoded = disasm_address_mask(dbg_get_cpu_mode(dbg), span, done, wildcard, starts);
    window = 0;
    if (decoded < FIND_MIN_USABLE)
        memset(wildcard, 0, done);
    else
        window = pick_window(span, wildcard, starts, done, len);
    pattern.bytes = span + window;
    pattern.wildcard = wildcard + window;
    pattern.len = len;
    usable = usable_count(pattern.wildcard, len);
    if (distinct_usable(&pattern) < FIND_MIN_DISTINCT && usable >= FIND_MIN_DISTINCT) {
        dbg_out(dbg, DBG_OUT_ERROR,
                "the bytes at %llx are nearly all the same (%02x...) and would match "
                "everywhere; pick an address with code or data\n",
                (unsigned long long)addr, span[0]);
        return DBG_E_BADARG;
    }
    if (usable < FIND_MIN_USABLE && usable < len) {
        dbg_out(dbg, DBG_OUT_ERROR,
                "only %u of %u bytes are left after masking addresses; use a larger L\n",
                usable, len);
        return DBG_E_BADARG;
    }
    dbg_out(dbg, DBG_OUT_NORMAL, "searching %u bytes at %llx (%s, %u masked as addresses)\n", len,
            (unsigned long long)(addr + window), decoded < FIND_MIN_USABLE ? "data" : "code",
            len - usable);

    memset(&state, 0, sizeof state);
    state.dbg = dbg;
    state.dir = dir_text;
    state.extension = normalized;
    state.pattern = &pattern;
    state.addr = addr + window;
    state.matches = matches;
    state.max = max;
    state.status = DBG_OK;
    walk_dirs(dbg, dirs, dir_text, search_file, &state);
    *count = state.count;
    *files_searched = state.files;
    return state.status;
}

static bool header_magic(const uint8_t *bytes)
{
    return !memcmp(bytes, "MZ", 2) || !memcmp(bytes, "VZ", 2) || !memcmp(bytes, "\x7f" "ELF", 4);
}

static bool read_failed(dbg_status status)
{
    return status != DBG_OK && status != DBG_E_FAULT && status != DBG_E_PARTIAL;
}

static void module_name_from(const char *path, char *name, size_t cap)
{
    const char *start;
    const char *cursor;
    const char *dot;
    size_t      len;

    start = path;
    for (cursor = path; *cursor; cursor++)
        if (*cursor == '/' || *cursor == '\\' || *cursor == ':')
            start = cursor + 1;
    dot = strrchr(start, '.');
    len = dot && dot != start ? (size_t)(dot - start) : strlen(start);
    if (len >= cap)
        len = cap - 1;
    memcpy(name, start, len);
    name[len] = '\0';
}

static uint32_t read_codeview(dbg_ctx *dbg, uint8_t space, uint64_t base,
                              const image_header *header, uint8_t *record, uint32_t cap)
{
    uint8_t  entries[DEBUG_ENTRIES_READ];
    uint32_t entries_len;
    uint32_t record_rva;
    uint32_t record_size;
    uint32_t done;

    done = 0;
    if (!header->debug_rva || !header->debug_size)
        return 0;
    entries_len = header->debug_size < sizeof entries ? header->debug_size
                                                      : (uint32_t)sizeof entries;
    if (read_failed(dbg_read_mem(dbg, space, base + header->debug_rva, entries, entries_len,
                                 &done)))
        return 0;
    if (!image_debug_record(entries, done, &record_rva, &record_size))
        return 0;
    if (record_size > cap)
        record_size = cap;
    done = 0;
    if (read_failed(dbg_read_mem(dbg, space, base + record_rva, record, record_size, &done)))
        return 0;
    return done;
}

static void read_debug_name(dbg_ctx *dbg, uint8_t space, const image_header *header,
                            dbg_image *out)
{
    uint8_t  record[RECORD_READ];
    uint32_t size;

    size = read_codeview(dbg, space, out->base, header, record, sizeof record);
    if (image_codeview_path(record, size, out->debug_path, sizeof out->debug_path))
        module_name_from(out->debug_path, out->name, sizeof out->name);
}

bool image_pdb_id(dbg_ctx *dbg, uint64_t base, uint8_t *guid, uint32_t *age)
{
    image_header header;
    uint8_t      data[HEADER_READ];
    uint8_t      record[RECORD_READ];
    uint8_t      space;
    uint32_t     done;
    uint32_t     size;

    done = 0;
    if (dbg->state != DBG_STATE_STOPPED || !dbg_regs(dbg))
        return false;
    space = paging_enabled(dbg) ? EM_SPACE_VIRT : EM_SPACE_PHYS;
    if (read_failed(dbg_read_mem(dbg, space, base, data, sizeof data, &done)) || done < 4 ||
        !image_parse_header(data, done, &header) || header.format != DBG_IMAGE_PE)
        return false;
    size = read_codeview(dbg, space, base, &header, record, sizeof record);
    if (size < 24 || memcmp(record, "RSDS", 4))
        return false;
    memcpy(guid, record + 4, 16);
    *age = (uint32_t)record[20] | (uint32_t)record[21] << 8 | (uint32_t)record[22] << 16 |
           (uint32_t)record[23] << 24;
    return true;
}

static void read_build_id(dbg_ctx *dbg, uint8_t space, const image_header *header,
                          dbg_image *out)
{
    uint8_t  notes[NOTES_READ];
    uint32_t index;
    uint32_t len;
    uint32_t done;

    for (index = 0; index < header->note_count; index++) {
        len = header->note_size[index] < sizeof notes ? (uint32_t)header->note_size[index]
                                                      : (uint32_t)sizeof notes;
        done = 0;
        if (read_failed(dbg_read_mem(dbg, space, out->base + header->note_vaddr[index], notes,
                                     len, &done)))
            return;
        if (image_build_id(notes, done, out->build_id, sizeof out->build_id,
                           &out->build_id_len))
            return;
    }
}

static void match_file(void *user, const char *name)
{
    image_search *search;
    image_header  header;
    uint8_t       data[HEADER_READ];
    char          path[DBG_FIND_PATH];
    FILE         *file;
    size_t        size;

    search = user;
    if (search->out->file[0])
        return;
    if (snprintf(path, sizeof path, "%s/%s", search->dir, name) >= (int)sizeof path)
        return;
    file = fopen(path, "rb");
    if (!file)
        return;
    size = fread(data, 1, sizeof data, file);
    fclose(file);
    if (size < 4 || !header_magic(data) || !image_parse_header(data, size, &header) ||
        header.fingerprint != search->header->fingerprint)
        return;
    snprintf(search->out->file, sizeof search->out->file, "%s", path);
}

static bool try_header(dbg_ctx *dbg, uint8_t space, uint64_t header_addr, uint64_t addr,
                       bool identify, dbg_image *out)
{
    image_header header;
    image_search search;
    uint8_t      data[HEADER_READ];
    char         dir_text[DBG_FIND_PATH];
    uint32_t     done;

    done = 0;
    if (read_failed(dbg_read_mem(dbg, space, header_addr, data, sizeof data, &done)))
        return false;
    if (done < 4 || !image_parse_header(data, done, &header) || header_addr < header.base_delta)
        return false;
    out->format = header.format;
    out->header = header_addr;
    out->base = header_addr - header.base_delta;
    out->size = header.size;
    out->contains = addr >= out->base && addr - out->base < out->size;
    if (!out->contains || !identify)
        return true;
    if (header.format == DBG_IMAGE_ELF)
        read_build_id(dbg, space, &header, out);
    else
        read_debug_name(dbg, space, &header, out);
    if (!out->name[0] && *dbg_get_exe_path(dbg)) {
        search.header = &header;
        search.out = out;
        search.dir = dir_text;
        walk_dirs(dbg, dbg_get_exe_path(dbg), dir_text, match_file, &search);
        if (out->file[0])
            module_name_from(out->file, out->name, sizeof out->name);
    }
    return true;
}

static bool page_has_magic(dbg_ctx *dbg, uint8_t space, uint64_t page, bool *readable)
{
    uint8_t  probe[4];
    uint32_t done;

    done = 0;
    if (read_failed(dbg_read_mem(dbg, space, page, probe, sizeof probe, &done)) ||
        done < sizeof probe) {
        *readable = false;
        return false;
    }
    return header_magic(probe);
}

static dbg_status walk_image(dbg_ctx *dbg, uint64_t addr, bool identify, dbg_image *out)
{
    uint8_t   *chunk;
    uint64_t   top;
    uint64_t   start;
    uint64_t   floor;
    uint64_t   candidate;
    uint32_t   len;
    uint32_t   done;
    uint8_t    space;
    bool       readable;
    bool       magic;
    bool       found;
    dbg_status status;

    memset(out, 0, sizeof *out);
    if (dbg->state == DBG_STATE_DISCONNECTED)
        return DBG_E_DISCONNECTED;
    chunk = malloc(WALK_CHUNK);
    if (!chunk)
        return DBG_E_NOMEM;
    space = paging_enabled(dbg) ? EM_SPACE_VIRT : EM_SPACE_PHYS;
    top = addr & ~(uint64_t)(WALK_PAGE - 1);
    floor = top >= WALK_LIMIT ? top - WALK_LIMIT : 0;
    out->lowest = top;
    found = false;
    readable = true;
    for (;;) {
        start = top - floor >= WALK_CHUNK - WALK_PAGE ? top - (WALK_CHUNK - WALK_PAGE) : floor;
        len = (uint32_t)(top + WALK_PAGE - start);
        done = 0;
        status = dbg_read_mem(dbg, space, start, chunk, len, &done);
        if (read_failed(status)) {
            free(chunk);
            return status;
        }
        for (candidate = top;; candidate -= WALK_PAGE) {
            if (done == len)
                magic = header_magic(chunk + (candidate - start));
            else
                magic = page_has_magic(dbg, space, candidate, &readable);
            if (!readable)
                break;
            out->lowest = candidate;
            if (magic && try_header(dbg, space, candidate, addr, identify, out)) {
                found = true;
                break;
            }
            if (candidate == start)
                break;
        }
        if (found || !readable || start == floor)
            break;
        top = start - WALK_PAGE;
    }
    free(chunk);
    if (!found)
        out->format = DBG_IMAGE_NONE;
    return DBG_OK;
}

dbg_status dbg_find_image(dbg_ctx *dbg, uint64_t addr, dbg_image *out)
{
    return walk_image(dbg, addr, true, out);
}

bool image_locate(dbg_ctx *dbg, uint64_t addr, uint64_t *base)
{
    dbg_image image;

    if (walk_image(dbg, addr, false, &image) != DBG_OK || image.format != DBG_IMAGE_PE ||
        !image.contains)
        return false;
    *base = image.base;
    return true;
}
