#include "dbg.h"
#include "image.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IDS_MAGIC        "EIDS"
#define IDS_VERSION      1u
#define IDS_VERSION_SECTIONS 2u
#define IDS_NAME_SIZE    64u
#define IDS_PATH_SIZE    260u
#define IDS_HEADER_SIZE  (4u + 4u + 8u + 8u + IDS_PATH_SIZE)
#define IDS_FUNC_SIZE    (IDS_NAME_SIZE + 8u + 8u)
#define IDS_LINE_SIZE    24u
#define PDB_MAGIC        "Microsoft C/C++ MSF 7.00"
#define SCAN_CHUNK       0x10000u
#define SCAN_PAGE        0x1000u
#define SCAN_MAX_HITS    16
#define CR0_PG           0x80000000u

static const char *const symbol_extensions[] = { ".ids", ".pdb" };
static const char *const image_extensions[] = { ".efi", ".dll", ".exe", ".sys" };

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

static uint64_t read_u64(const uint8_t *bytes)
{
    return (uint64_t)read_u32(bytes) | (uint64_t)read_u32(bytes + 4) << 32;
}

static char *dup_text(const char *text, size_t len)
{
    char *copy;

    copy = malloc(len + 1);
    if (!copy)
        return NULL;
    memcpy(copy, text, len);
    copy[len] = '\0';
    return copy;
}

static bool is_separator(char ch)
{
    return ch == '/' || ch == '\\';
}

static bool is_absolute(const char *path)
{
    if (is_separator(path[0]))
        return true;
    return isalpha((unsigned char)path[0]) && path[1] == ':';
}

static const char *base_name(const char *path)
{
    const char *cursor;
    const char *name;

    name = path;
    for (cursor = path; *cursor; cursor++)
        if (is_separator(*cursor) || *cursor == ':')
            name = cursor + 1;
    return name;
}

static bool names_equal(const char *left, const char *right)
{
    while (*left && tolower((unsigned char)*left) == tolower((unsigned char)*right)) {
        left++;
        right++;
    }
    return *left == '\0' && *right == '\0';
}

static bool names_equal_len(const char *name, const char *text, size_t len)
{
    size_t index;

    for (index = 0; index < len; index++)
        if (!name[index] || tolower((unsigned char)name[index]) != tolower((unsigned char)text[index]))
            return false;
    return name[len] == '\0';
}

static bool paths_equal(const char *left, const char *right)
{
    char left_ch;
    char right_ch;

    for (;;) {
        left_ch = is_separator(*left) ? '/' : (char)tolower((unsigned char)*left);
        right_ch = is_separator(*right) ? '/' : (char)tolower((unsigned char)*right);
        if (left_ch != right_ch)
            return false;
        if (!left_ch)
            return true;
        left++;
        right++;
    }
}

static bool file_exists(const char *path)
{
    FILE *file;

    file = fopen(path, "rb");
    if (!file)
        return false;
    fclose(file);
    return true;
}

static char *join_existing(const char *dir, size_t dir_len, const char *name)
{
    char  *path;
    size_t name_len;

    while (dir_len && is_separator(dir[dir_len - 1]))
        dir_len--;
    while (is_separator(*name))
        name++;
    if (!dir_len || !*name)
        return NULL;
    name_len = strlen(name);
    path = malloc(dir_len + 1 + name_len + 1);
    if (!path)
        return NULL;
    memcpy(path, dir, dir_len);
    path[dir_len] = '/';
    memcpy(path + dir_len + 1, name, name_len + 1);
    if (file_exists(path))
        return path;
    free(path);
    return NULL;
}

static char *search_dirs(const char *dirs, const char *name)
{
    const char *dir;
    const char *dir_end;
    const char *suffix;
    char       *found;

    if (!dirs)
        return NULL;
    for (dir = dirs; *dir; dir = *dir_end ? dir_end + 1 : dir_end) {
        dir_end = strchr(dir, ';');
        if (!dir_end)
            dir_end = dir + strlen(dir);
        found = NULL;
        if (!is_absolute(name))
            found = join_existing(dir, (size_t)(dir_end - dir), name);
        for (suffix = name; *suffix && !found; suffix++)
            if (is_separator(*suffix) || *suffix == ':')
                found = join_existing(dir, (size_t)(dir_end - dir), suffix + 1);
        if (found)
            return found;
    }
    return NULL;
}

static char *locate(const char *dirs, const char *path)
{
    if (file_exists(path))
        return dup_text(path, strlen(path));
    return search_dirs(dirs, path);
}

static char *find_symbol_file(const dbg_ctx *dbg, const char *file)
{
    char  *found;
    char  *candidate;
    size_t len;
    size_t extension_len;
    size_t index;

    found = locate(dbg->sym_path, file);
    if (found || strchr(base_name(file), '.'))
        return found;
    len = strlen(file);
    for (index = 0; index < sizeof symbol_extensions / sizeof symbol_extensions[0] && !found;
         index++) {
        extension_len = strlen(symbol_extensions[index]);
        candidate = malloc(len + extension_len + 1);
        if (!candidate)
            return NULL;
        memcpy(candidate, file, len);
        memcpy(candidate + len, symbol_extensions[index], extension_len + 1);
        found = locate(dbg->sym_path, candidate);
        free(candidate);
    }
    return found;
}

uint8_t *sym_read_file(const char *path, size_t *size)
{
    FILE    *file;
    uint8_t *data;
    long     length;

    data = NULL;
    file = fopen(path, "rb");
    if (!file)
        return NULL;
    if (fseek(file, 0, SEEK_END) == 0) {
        length = ftell(file);
        if (length > 0 && fseek(file, 0, SEEK_SET) == 0) {
            data = malloc((size_t)length);
            if (data && fread(data, 1, (size_t)length, file) != (size_t)length) {
                free(data);
                data = NULL;
            }
            *size = (size_t)length;
        }
    }
    fclose(file);
    return data;
}

static char *module_name_of(const char *path)
{
    const char *name;
    const char *dot;

    name = base_name(path);
    dot = strrchr(name, '.');
    return dup_text(name, dot && dot != name ? (size_t)(dot - name) : strlen(name));
}

static void module_free(sym_module *module)
{
    uint32_t index;

    for (index = 0; index < module->file_count; index++) {
        free(module->files[index].path);
        free(module->files[index].resolved);
        free((void *)module->files[index].by_line);
    }
    free(module->files);
    free((void *)module->by_name);
    free((void *)module->globals_by_name);
    free(module->lines);
    free(module->funcs);
    free(module->names);
    free(module->strings);
    free(module->types);
    free(module->members);
    free(module->enumerators);
    free(module->vars);
    free(module->globals);
    free(module->locations);
    free(module->cfas);
    free(module->name);
    free(module->symbol_file);
}

static int compare_funcs(const void *left, const void *right)
{
    const sym_func *left_func;
    const sym_func *right_func;

    left_func = left;
    right_func = right;
    if (left_func->start == right_func->start)
        return 0;
    return left_func->start < right_func->start ? -1 : 1;
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

static int compare_func_names(const void *left, const void *right)
{
    const sym_func *const *left_func;
    const sym_func *const *right_func;

    left_func = left;
    right_func = right;
    return strcmp((*left_func)->name, (*right_func)->name);
}

static int compare_line_numbers(const void *left, const void *right)
{
    const sym_line *const *left_line;
    const sym_line *const *right_line;

    left_line = left;
    right_line = right;
    if ((*left_line)->line != (*right_line)->line)
        return (*left_line)->line < (*right_line)->line ? -1 : 1;
    if ((*left_line)->start == (*right_line)->start)
        return 0;
    return (*left_line)->start < (*right_line)->start ? -1 : 1;
}

static int compare_var_names(const void *left, const void *right)
{
    const sym_var *const *left_var;
    const sym_var *const *right_var;

    left_var = left;
    right_var = right;
    return strcmp((*left_var)->name, (*right_var)->name);
}

static dbg_status module_build_index(sym_module *module)
{
    sym_file *file;
    uint32_t  index;

    module->by_name = malloc((module->pub.function_count ? module->pub.function_count : 1) *
                             sizeof *module->by_name);
    if (!module->by_name)
        return DBG_E_NOMEM;
    for (index = 0; index < module->pub.function_count; index++)
        module->by_name[index] = &module->funcs[index];
    qsort((void *)module->by_name, module->pub.function_count, sizeof *module->by_name,
          compare_func_names);

    module->globals_by_name = malloc((module->pub.global_count ? module->pub.global_count : 1) *
                                     sizeof *module->globals_by_name);
    if (!module->globals_by_name)
        return DBG_E_NOMEM;
    for (index = 0; index < module->pub.global_count; index++)
        module->globals_by_name[index] = &module->globals[index];
    qsort((void *)module->globals_by_name, module->pub.global_count,
          sizeof *module->globals_by_name, compare_var_names);

    for (index = 0; index < module->pub.line_count; index++)
        module->files[module->lines[index].file].by_line_count++;
    for (index = 0; index < module->file_count; index++) {
        file = &module->files[index];
        file->by_line = malloc((file->by_line_count ? file->by_line_count : 1) *
                               sizeof *file->by_line);
        if (!file->by_line)
            return DBG_E_NOMEM;
        file->by_line_count = 0;
    }
    for (index = 0; index < module->pub.line_count; index++) {
        file = &module->files[module->lines[index].file];
        file->by_line[file->by_line_count++] = &module->lines[index];
    }
    for (index = 0; index < module->file_count; index++)
        qsort((void *)module->files[index].by_line, module->files[index].by_line_count,
              sizeof *module->files[index].by_line, compare_line_numbers);
    return DBG_OK;
}

static dbg_status ids_truncated(dbg_ctx *dbg, const sym_module *module)
{
    dbg_out(dbg, DBG_OUT_ERROR, "%s: truncated .ids file\n", module->symbol_file);
    return DBG_E_BADARG;
}

static dbg_status ids_parse(dbg_ctx *dbg, sym_module *module, const uint8_t *data, size_t size)
{
    const uint8_t *cursor;
    const uint8_t *data_end;
    const uint8_t *record;
    const char    *path;
    const char    *path_end;
    sym_func      *func;
    sym_line      *entry;
    char          *name;
    uint64_t       function_count;
    uint64_t       function_index;
    uint64_t       line_count;
    uint64_t       line_index;
    uint64_t       total_lines;
    uint64_t       start;
    uint64_t       stop;
    uint64_t       line;
    uint64_t       base;
    size_t         path_len;

    base = module->pub.base;
    data_end = data + size;
    if (size >= 8 && read_u32(data + 4) == IDS_VERSION_SECTIONS)
        return ids_parse_v2(dbg, module, data, size);
    if (size < IDS_HEADER_SIZE)
        return ids_truncated(dbg, module);
    if (read_u32(data + 4) != IDS_VERSION) {
        dbg_out(dbg, DBG_OUT_ERROR, "%s: .ids version %u, expected %u\n", module->symbol_file,
                read_u32(data + 4), IDS_VERSION);
        return DBG_E_BADARG;
    }
    function_count = read_u64(data + 16);

    total_lines = 0;
    cursor = data + IDS_HEADER_SIZE;
    for (function_index = 0; function_index < function_count; function_index++) {
        if ((size_t)(data_end - cursor) < IDS_FUNC_SIZE)
            return ids_truncated(dbg, module);
        line_count = read_u64(cursor + IDS_NAME_SIZE + 8);
        cursor += IDS_FUNC_SIZE;
        if (line_count > (size_t)(data_end - cursor) / IDS_LINE_SIZE)
            return ids_truncated(dbg, module);
        cursor += line_count * IDS_LINE_SIZE;
        total_lines += line_count;
    }

    path = (const char *)data + 24;
    path_end = memchr(path, '\0', IDS_PATH_SIZE);
    path_len = path_end ? (size_t)(path_end - path) : IDS_PATH_SIZE;
    module->funcs = calloc(function_count ? (size_t)function_count : 1, sizeof *module->funcs);
    module->names = malloc(function_count ? (size_t)function_count * IDS_NAME_SIZE : 1);
    module->lines = calloc(total_lines ? (size_t)total_lines : 1, sizeof *module->lines);
    module->files = calloc(1, sizeof *module->files);
    if (!module->funcs || !module->names || !module->lines || !module->files)
        return DBG_E_NOMEM;
    module->files[0].path = dup_text(path, path_len);
    if (!module->files[0].path)
        return DBG_E_NOMEM;
    module->file_count = 1;

    cursor = data + IDS_HEADER_SIZE;
    for (function_index = 0; function_index < function_count; function_index++) {
        func = &module->funcs[function_index];
        name = module->names + function_index * IDS_NAME_SIZE;
        memcpy(name, cursor, IDS_NAME_SIZE);
        name[IDS_NAME_SIZE - 1] = '\0';
        func->name = name;
        func->start = base + read_u64(cursor + IDS_NAME_SIZE);
        func->end = func->start + 1;
        line_count = read_u64(cursor + IDS_NAME_SIZE + 8);
        cursor += IDS_FUNC_SIZE;
        for (line_index = 0; line_index < line_count; line_index++) {
            record = cursor + line_index * IDS_LINE_SIZE;
            start = read_u64(record);
            line = read_u64(record + 8);
            stop = read_u64(record + 16);
            if (stop <= start || line == 0 || line > UINT32_MAX)
                continue;
            entry = &module->lines[module->pub.line_count++];
            entry->start = base + start;
            entry->end = base + stop;
            entry->line = (uint32_t)line;
            entry->file = 0;
            if (entry->end > func->end)
                func->end = entry->end;
        }
        cursor += line_count * IDS_LINE_SIZE;
    }
    module->pub.function_count = (uint32_t)function_count;
    module->pub.end = base + read_u64(data + 8);
    return DBG_OK;
}

static void fix_module_end(sym_module *module)
{
    uint32_t index;

    if (module->pub.end <= module->pub.base)
        module->pub.end = module->pub.base + 1;
    for (index = 0; index < module->pub.function_count; index++)
        if (module->funcs[index].end > module->pub.end)
            module->pub.end = module->funcs[index].end;
}

static dbg_status module_insert(dbg_ctx *dbg, sym_module *module)
{
    sym_module *existing;
    sym_module *grown;
    int         index;
    int         position;

    index = 0;
    while (index < dbg->module_count) {
        existing = &dbg->modules[index];
        if (names_equal(existing->name, module->name) ||
            (module->pub.base < existing->pub.end && existing->pub.base < module->pub.end)) {
            dbg_out(dbg, DBG_OUT_NORMAL, "unloading %s\n", existing->name);
            module_free(existing);
            memmove(existing, existing + 1,
                    (size_t)(dbg->module_count - index - 1) * sizeof *existing);
            dbg->module_count--;
        } else {
            index++;
        }
    }

    grown = realloc(dbg->modules, (size_t)(dbg->module_count + 1) * sizeof *grown);
    if (!grown)
        return DBG_E_NOMEM;
    dbg->modules = grown;
    position = 0;
    while (position < dbg->module_count && dbg->modules[position].pub.base < module->pub.base)
        position++;
    memmove(&dbg->modules[position + 1], &dbg->modules[position],
            (size_t)(dbg->module_count - position) * sizeof *grown);
    dbg->modules[position] = *module;
    dbg->modules[position].pub.name = dbg->modules[position].name;
    dbg->modules[position].pub.symbol_file = dbg->modules[position].symbol_file;
    dbg->module_count++;
    return DBG_OK;
}

static dbg_status module_parse(dbg_ctx *dbg, const char *file, uint64_t base, sym_module *module)
{
    uint8_t   *data;
    size_t     size;
    dbg_status status;

    size = 0;
    memset(module, 0, sizeof *module);
    module->pub.base = base;
    module->symbol_file = find_symbol_file(dbg, file);
    if (!module->symbol_file) {
        dbg_out(dbg, DBG_OUT_ERROR, "%s: symbol file not found (symbol path: %s)\n", file,
                dbg_get_sym_path(dbg));
        return DBG_E_BADARG;
    }
    module->name = module_name_of(module->symbol_file);
    if (!module->name) {
        module_free(module);
        return DBG_E_NOMEM;
    }
    data = sym_read_file(module->symbol_file, &size);
    if (!data) {
        dbg_out(dbg, DBG_OUT_ERROR, "%s: cannot read the file\n", module->symbol_file);
        module_free(module);
        return DBG_E_BADARG;
    }

    if (size >= sizeof PDB_MAGIC - 1 && !memcmp(data, PDB_MAGIC, sizeof PDB_MAGIC - 1)) {
        status = pdb_parse(dbg, module, data, size);
    } else if (size >= 4 && !memcmp(data, IDS_MAGIC, 4)) {
        status = ids_parse(dbg, module, data, size);
    } else {
        dbg_out(dbg, DBG_OUT_ERROR,
                "%s: not an .ids or .pdb file (regenerate old .ids files with listDecomp.py)\n",
                module->symbol_file);
        status = DBG_E_BADARG;
    }
    free(data);

    if (status == DBG_OK) {
        qsort(module->funcs, module->pub.function_count, sizeof *module->funcs, compare_funcs);
        qsort(module->lines, module->pub.line_count, sizeof *module->lines, compare_lines);
        fix_module_end(module);
        status = module_build_index(module);
    }
    if (status != DBG_OK)
        module_free(module);
    return status;
}

static void module_rebase(sym_module *module, uint64_t base)
{
    uint32_t index;

    for (index = 0; index < module->pub.function_count; index++) {
        module->funcs[index].start += base;
        module->funcs[index].end += base;
    }
    for (index = 0; index < module->pub.line_count; index++) {
        module->lines[index].start += base;
        module->lines[index].end += base;
    }
    module->pub.base += base;
    module->pub.end += base;
}


/*
* add a module, in case there is another module on the same address, unload it and load the current one
*/
static dbg_status module_add(dbg_ctx *dbg, sym_module *module)
{
    dbg_status status;

    status = module_insert(dbg, module);
    if (status != DBG_OK) {
        module_free(module);
        return status;
    }
    if (module->pub.type_count > 1 || module->pub.global_count)
        dbg_out(dbg, DBG_OUT_NORMAL, "Module added with name %s: %08" PRIx64 "-%08" PRIx64
                ", %u functions, %u lines, %u types, %u locals, %u globals, %s\n",
                module->name, module->pub.base, module->pub.end, module->pub.function_count,
                module->pub.line_count, module->pub.type_count - 1, module->var_count,
                module->pub.global_count, module->symbol_file);
    else
        dbg_out(dbg, DBG_OUT_NORMAL, "Module added with name %s: %08" PRIx64 "-%08" PRIx64
                ", %u functions, %u lines, %s\n",
                module->name, module->pub.base, module->pub.end, module->pub.function_count,
                module->pub.line_count, module->symbol_file);
    return DBG_OK;
}

static void check_pdb_match(dbg_ctx *dbg, const sym_module *module)
{
    uint8_t  guid[16];
    uint32_t age;

    if (!module->has_pdb_id || !image_pdb_id(dbg, module->pub.base, guid, &age))
        return;
    if (!memcmp(guid, module->pdb_guid, sizeof guid) && age == module->pdb_age)
        return;
    dbg_out(dbg, DBG_OUT_ERROR,
            "warning: %s does not match the image at %016" PRIx64
            " (PDB age %u, image age %u%s): lines and names may be wrong\n",
            module->symbol_file, module->pub.base, module->pdb_age, age,
            memcmp(guid, module->pdb_guid, sizeof guid) ? ", different GUID" : "");
}

dbg_status dbg_sym_load(dbg_ctx *dbg, const char *file, uint64_t base)
{
    sym_module module;
    dbg_status status;

    status = module_parse(dbg, file, base, &module);
    if (status != DBG_OK)
        return status;
    check_pdb_match(dbg, &module);
    return module_add(dbg, &module);
}

static char *find_image_file(const dbg_ctx *dbg, const sym_module *module)
{
    char  *found;
    char  *name;
    size_t dir_len;
    size_t name_len;
    size_t extension_len;
    size_t index;

    found = NULL;
    dir_len = (size_t)(base_name(module->symbol_file) - module->symbol_file);
    name_len = strlen(module->name);
    for (index = 0; index < sizeof image_extensions / sizeof image_extensions[0] && !found;
         index++) {
        extension_len = strlen(image_extensions[index]);
        name = malloc(name_len + extension_len + 1);
        if (!name)
            return NULL;
        memcpy(name, module->name, name_len);
        memcpy(name + name_len, image_extensions[index], extension_len + 1);
        if (dir_len)
            found = join_existing(module->symbol_file, dir_len, name);
        if (!found)
            found = search_dirs(dbg->exe_path, name);
        if (!found)
            found = locate(dbg->sym_path, name);
        free(name);
    }
    return found;
}

bool paging_enabled(const dbg_ctx *dbg)
{
    if (!(dbg->regs.valid & EM_RB_BIT(EM_RB_X86_CTRL)))
        return false;
    return (dbg->regs.ctrl.cr0 & CR0_PG) != 0;
}

static bool scan_fatal(dbg_status status)
{
    return status != DBG_OK && status != DBG_E_FAULT && status != DBG_E_PARTIAL;
}

static dbg_status scan_range(dbg_ctx *dbg, uint8_t space, const image_pattern *patterns,
                             uint64_t start, uint64_t end, uint64_t *bases, int *base_count)
{
    uint8_t   *buf;
    uint8_t    check[IMAGE_PATTERN_SIZE];
    uint64_t   addr;
    uint64_t   next;
    uint64_t   base;
    uint32_t   want;
    uint32_t   done;
    uint32_t   check_done;
    uint32_t   position;
    int        index;
    bool       known;
    dbg_status status;

    *base_count = 0;
    buf = malloc(SCAN_CHUNK);
    if (!buf)
        return DBG_E_NOMEM;
    addr = start;
    for (;;) {
        want = end - addr >= SCAN_CHUNK - 1 ? SCAN_CHUNK : (uint32_t)(end - addr) + 1;
        done = 0;
        status = dbg_read_mem(dbg, space, addr, buf, want, &done);
        if (scan_fatal(status)) {
            free(buf);
            return status;
        }
        for (position = 0; position + IMAGE_PATTERN_SIZE <= done; position++) {
            if (buf[position] != patterns[0].bytes[0] ||
                memcmp(buf + position, patterns[0].bytes, IMAGE_PATTERN_SIZE))
                continue;
            base = addr + position - patterns[0].rva;
            known = false;
            for (index = 0; index < *base_count; index++)
                known = known || bases[index] == base;
            if (known || *base_count == SCAN_MAX_HITS)
                continue;
            check_done = 0;
            status = dbg_read_mem(dbg, space, base + patterns[1].rva, check, IMAGE_PATTERN_SIZE,
                                  &check_done);
            if (scan_fatal(status)) {
                free(buf);
                return status;
            }
            if (check_done == IMAGE_PATTERN_SIZE &&
                !memcmp(check, patterns[1].bytes, IMAGE_PATTERN_SIZE))
                bases[(*base_count)++] = base;
        }
        if (done < want)
            next = ((addr + done) | (SCAN_PAGE - 1)) + 1;
        else if (end - addr < want)
            break;
        else
            next = addr + want - (IMAGE_PATTERN_SIZE - 1);
        if (next <= addr || next > end)
            break;
        addr = next;
    }
    free(buf);
    return DBG_OK;
}
/*
* Scans a memory range trying to find the executable image in it and prints the results to the user.
* In case paging is enabled it will look in VA address space otherwise in to PA.
* The search is done by using patterns that don't exist in relocation table.
*/
dbg_status dbg_sym_scan(dbg_ctx *dbg, const char *file, uint64_t start, uint64_t end)
{
    sym_module    module;
    image_pattern patterns[2];
    uint64_t      bases[SCAN_MAX_HITS];
    uint8_t      *data;
    char         *image_path;
    size_t        size;
    uint8_t       space;
    int           base_count;
    int           index;
    dbg_status    status;

    size = 0;
    base_count = 0;
    if (dbg->state != DBG_STATE_STOPPED)
        return dbg->state == DBG_STATE_DISCONNECTED ? DBG_E_DISCONNECTED : DBG_E_RUNNING;
    if (end < start)
        return DBG_E_BADARG;
    /* parse symbol file */
    status = module_parse(dbg, file, 0, &module);
    if (status != DBG_OK)
        return status;
    /* find executetable image path in symbol file, executable directories */
    image_path = find_image_file(dbg, &module);
    if (!image_path) {
        dbg_out(dbg, DBG_OUT_ERROR,
                "%s: image (.efi/.dll/.exe/.sys) not found next to %s, in the executable "
                "folders or in the symbol folders\n",
                module.name, module.symbol_file);
        module_free(&module);
        return DBG_E_BADARG;
    }
    /* read image to find non relocatable bytes-patterns */
    data = sym_read_file(image_path, &size);
    if (!data) {
        dbg_out(dbg, DBG_OUT_ERROR, "%s: cannot read the file\n", image_path);
        status = DBG_E_BADARG;
    } else {
        status = image_find_patterns(dbg, image_path, data, size, &module, patterns);
    }
    free(data);
    free(image_path);

    space = paging_enabled(dbg) ? EM_SPACE_VIRT : EM_SPACE_PHYS;
    if (status == DBG_OK) {
        dbg_out(dbg, DBG_OUT_NORMAL,
                "scanning %s %08" PRIx64 "-%08" PRIx64 " for %s (rva %x and %x)\n",
                space == EM_SPACE_VIRT ? "virtual" : "physical", start, end, module.name,
                patterns[0].rva, patterns[1].rva);
        /* memcmp the range to find the patterns, print them to the user */
        status = scan_range(dbg, space, patterns, start, end, bases, &base_count);
    }
    /* if not found, or there is more than one occurance*/
    if (status == DBG_OK && base_count != 1) {
        if (base_count == 0)
            dbg_out(dbg, DBG_OUT_ERROR, "%s: not found in the range\n", module.name);
        for (index = 0; index < base_count; index++)
            dbg_out(dbg, DBG_OUT_NORMAL, "lds %s %08" PRIx64 "\n", module.name,
                    bases[index]);
        status = DBG_E_BADARG;
    }

    if (status != DBG_OK) {
        module_free(&module);
        return status;
    }
    
    module_rebase(&module, bases[0]);
    return module_add(dbg, &module);
    
}

void sym_free_all(dbg_ctx *dbg)
{
    int index;

    for (index = 0; index < dbg->module_count; index++)
        module_free(&dbg->modules[index]);
    free(dbg->modules);
    free(dbg->sym_path);
    free(dbg->src_path);
    free(dbg->exe_path);
    dbg->modules = NULL;
    dbg->module_count = 0;
    dbg->sym_path = NULL;
    dbg->src_path = NULL;
    dbg->exe_path = NULL;
}

static dbg_status set_path(char **slot, const char *dirs)
{
    char *copy;

    copy = NULL;
    if (dirs && *dirs) {
        copy = dup_text(dirs, strlen(dirs));
        if (!copy)
            return DBG_E_NOMEM;
    }
    free(*slot);
    *slot = copy;
    return DBG_OK;
}

dbg_status dbg_set_sym_path(dbg_ctx *dbg, const char *dirs)
{
    return set_path(&dbg->sym_path, dirs);
}

dbg_status dbg_set_src_path(dbg_ctx *dbg, const char *dirs)
{
    sym_file  *file;
    dbg_status status;
    int        module_index;
    uint32_t   file_index;

    status = set_path(&dbg->src_path, dirs);
    if (status != DBG_OK)
        return status;
    for (module_index = 0; module_index < dbg->module_count; module_index++) {
        for (file_index = 0; file_index < dbg->modules[module_index].file_count; file_index++) {
            file = &dbg->modules[module_index].files[file_index];
            free(file->resolved);
            file->resolved = NULL;
            file->searched = false;
        }
    }
    return DBG_OK;
}

dbg_status dbg_set_exe_path(dbg_ctx *dbg, const char *dirs)
{
    return set_path(&dbg->exe_path, dirs);
}

const char *dbg_get_exe_path(const dbg_ctx *dbg)
{
    return dbg->exe_path ? dbg->exe_path : "";
}

const char *dbg_get_sym_path(const dbg_ctx *dbg)
{
    return dbg->sym_path ? dbg->sym_path : "";
}

const char *dbg_get_src_path(const dbg_ctx *dbg)
{
    return dbg->src_path ? dbg->src_path : "";
}

int dbg_module_count(const dbg_ctx *dbg)
{
    return dbg->module_count;
}

const dbg_module *dbg_module_get(const dbg_ctx *dbg, int index)
{
    if (index < 0 || index >= dbg->module_count)
        return NULL;
    return &dbg->modules[index].pub;
}

static int module_index_at(const dbg_ctx *dbg, uint64_t addr)
{
    int low;
    int high;
    int middle;

    low = 0;
    high = dbg->module_count;
    while (low < high) {
        middle = low + (high - low) / 2;
        if (dbg->modules[middle].pub.base <= addr)
            low = middle + 1;
        else
            high = middle;
    }
    if (low == 0 || addr >= dbg->modules[low - 1].pub.end)
        return -1;
    return low - 1;
}

static const sym_func *func_at(const sym_module *module, uint64_t addr)
{
    uint32_t low;
    uint32_t high;
    uint32_t middle;

    low = 0;
    high = module->pub.function_count;
    while (low < high) {
        middle = low + (high - low) / 2;
        if (module->funcs[middle].start <= addr)
            low = middle + 1;
        else
            high = middle;
    }
    if (low == 0 || addr >= module->funcs[low - 1].end)
        return NULL;
    return &module->funcs[low - 1];
}

static const sym_line *line_at(const sym_module *module, uint64_t addr)
{
    uint32_t low;
    uint32_t high;
    uint32_t middle;

    low = 0;
    high = module->pub.line_count;
    while (low < high) {
        middle = low + (high - low) / 2;
        if (module->lines[middle].start <= addr)
            low = middle + 1;
        else
            high = middle;
    }
    if (low == 0 || addr >= module->lines[low - 1].end)
        return NULL;
    return &module->lines[low - 1];
}

bool dbg_sym_name(const dbg_ctx *dbg, uint64_t addr, dbg_symbol *out)
{
    const sym_module *module;
    const sym_func   *func;
    int               index;

    index = module_index_at(dbg, addr);
    if (index < 0)
        return false;
    module = &dbg->modules[index];
    func = func_at(module, addr);
    out->module = module->name;
    out->function = func ? func->name : NULL;
    out->offset = addr - (func ? func->start : module->pub.base);
    return true;
}

bool dbg_sym_format(const dbg_ctx *dbg, uint64_t addr, char *buf, size_t cap)
{
    dbg_symbol symbol;

    if (!dbg_sym_name(dbg, addr, &symbol))
        return false;
    if (symbol.function && symbol.offset)
        snprintf(buf, cap, "%s!%s+0x%" PRIx64, symbol.module, symbol.function, symbol.offset);
    else if (symbol.function)
        snprintf(buf, cap, "%s!%s", symbol.module, symbol.function);
    else
        snprintf(buf, cap, "%s+0x%" PRIx64, symbol.module, symbol.offset);
    return true;
}

static int compare_name_text(const char *name, const char *text, size_t len)
{
    int order;

    order = strncmp(name, text, len);
    if (order)
        return order;
    return name[len] ? 1 : 0;
}

static bool func_addr(const sym_module *module, const char *name, size_t len, uint64_t *addr)
{
    uint32_t low;
    uint32_t high;
    uint32_t middle;
    int      order;

    low = 0;
    high = module->pub.function_count;
    while (low < high) {
        middle = low + (high - low) / 2;
        order = compare_name_text(module->by_name[middle]->name, name, len);
        if (order == 0) {
            *addr = module->by_name[middle]->start;
            return true;
        }
        if (order < 0)
            low = middle + 1;
        else
            high = middle;
    }
    return false;
}

bool dbg_sym_addr(const dbg_ctx *dbg, const char *name, size_t len, uint64_t *addr)
{
    const sym_module *module;
    const char       *bang;
    size_t            module_len;
    int               index;

    bang = memchr(name, '!', len);
    module_len = bang ? (size_t)(bang - name) : len;
    for (index = 0; index < dbg->module_count; index++) {
        module = &dbg->modules[index];
        if (!names_equal_len(module->name, name, module_len))
            continue;
        if (!bang || bang + 1 == name + len) {
            *addr = module->pub.base;
            return true;
        }
        return func_addr(module, bang + 1, (size_t)(name + len - bang - 1), addr);
    }
    if (bang)
        return false;
    for (index = 0; index < dbg->module_count; index++)
        if (func_addr(&dbg->modules[index], name, len, addr))
            return true;
    return false;
}

static bool glob_match(const char *pattern, size_t pattern_len, const char *text)
{
    const char *star_text;
    size_t      pattern_pos;
    size_t      star_pos;
    bool        have_star;

    pattern_pos = 0;
    star_pos = 0;
    star_text = NULL;
    have_star = false;
    while (*text) {
        if (pattern_pos < pattern_len && pattern[pattern_pos] == '*') {
            have_star = true;
            star_pos = ++pattern_pos;
            star_text = text;
        } else if (pattern_pos < pattern_len &&
                   (pattern[pattern_pos] == '?' ||
                    tolower((unsigned char)pattern[pattern_pos]) == tolower((unsigned char)*text))) {
            pattern_pos++;
            text++;
        } else if (have_star) {
            pattern_pos = star_pos;
            text = ++star_text;
        } else {
            return false;
        }
    }
    while (pattern_pos < pattern_len && pattern[pattern_pos] == '*')
        pattern_pos++;
    return pattern_pos == pattern_len;
}

int dbg_sym_enum(const dbg_ctx *dbg, const char *pattern, dbg_sym_fn fn, void *user)
{
    const sym_module *module;
    const sym_func   *func;
    const char       *bang;
    const char       *module_pattern;
    const char       *name_pattern;
    size_t            module_len;
    size_t            name_len;
    uint32_t          func_index;
    int               module_index;
    int               count;

    count = 0;
    bang = strchr(pattern, '!');
    module_pattern = bang ? pattern : "*";
    module_len = bang ? (size_t)(bang - pattern) : 1;
    name_pattern = bang ? bang + 1 : pattern;
    name_len = strlen(name_pattern);
    if (!name_len) {
        name_pattern = "*";
        name_len = 1;
    }
    for (module_index = 0; module_index < dbg->module_count; module_index++) {
        module = &dbg->modules[module_index];
        if (!glob_match(module_pattern, module_len, module->name))
            continue;
        for (func_index = 0; func_index < module->pub.function_count; func_index++) {
            func = module->by_name[func_index];
            if (!glob_match(name_pattern, name_len, func->name))
                continue;
            count++;
            if (fn && !fn(user, module->name, func->name, func->start))
                return count;
        }
    }
    return count;
}

static const char *file_path(const dbg_ctx *dbg, sym_file *file)
{
    if (!file->searched) {
        file->resolved = locate(dbg->src_path, file->path);
        file->searched = true;
    }
    return file->resolved ? file->resolved : file->path;
}

bool dbg_source_at(dbg_ctx *dbg, uint64_t addr, dbg_source *out)
{
    sym_module     *module;
    sym_file       *file;
    const sym_func *func;
    const sym_line *line;
    int             index;

    index = module_index_at(dbg, addr);
    if (index < 0)
        return false;
    module = &dbg->modules[index];
    line = line_at(module, addr);
    if (!line)
        return false;
    file = &module->files[line->file];
    func = func_at(module, addr);
    out->module = module->name;
    out->function = func ? func->name : NULL;
    out->file = file_path(dbg, file);
    out->file_found = file->resolved != NULL;
    out->line = line->line;
    out->start = line->start;
    out->end = line->end;
    return true;
}

static const sym_line *first_line_from(const sym_file *source, uint32_t line)
{
    uint32_t low;
    uint32_t high;
    uint32_t middle;

    low = 0;
    high = source->by_line_count;
    while (low < high) {
        middle = low + (high - low) / 2;
        if (source->by_line[middle]->line < line)
            low = middle + 1;
        else
            high = middle;
    }
    return low < source->by_line_count ? source->by_line[low] : NULL;
}

dbg_status dbg_line_addr(dbg_ctx *dbg, const char *file, uint32_t line, uint64_t *addr)
{
    const sym_line *entry;
    const sym_line *best;
    sym_file       *source;
    int             module_index;
    uint32_t        file_index;

    best = NULL;
    for (module_index = 0; module_index < dbg->module_count; module_index++) {
        for (file_index = 0; file_index < dbg->modules[module_index].file_count; file_index++) {
            source = &dbg->modules[module_index].files[file_index];
            if (!paths_equal(file, source->path) && !paths_equal(file, file_path(dbg, source)))
                continue;
            entry = first_line_from(source, line);
            if (entry && (!best || entry->line < best->line ||
                          (entry->line == best->line && entry->start < best->start)))
                best = entry;
        }
    }
    if (!best)
        return DBG_E_BADARG;
    *addr = best->start;
    return DBG_OK;
}

sym_module *sym_module_at(dbg_ctx *dbg, uint64_t addr)
{
    int index;

    index = module_index_at(dbg, addr);
    return index < 0 ? NULL : &dbg->modules[index];
}

const sym_func *sym_func_in(const sym_module *module, uint64_t addr)
{
    return func_at(module, addr);
}

bool sym_line_at(dbg_ctx *dbg, uint64_t addr, sym_line_info *out)
{
    const sym_module *module;
    const sym_line   *line;
    int               index;

    index = module_index_at(dbg, addr);
    if (index < 0)
        return false;
    module = &dbg->modules[index];
    line = line_at(module, addr);
    if (!line)
        return false;
    out->module = module;
    out->file = line->file;
    out->line = line->line;
    out->start = line->start;
    out->end = line->end;
    return true;
}

uint64_t sym_func_start(dbg_ctx *dbg, uint64_t addr)
{
    const sym_func *func;
    int             index;

    index = module_index_at(dbg, addr);
    if (index < 0)
        return 0;
    func = func_at(&dbg->modules[index], addr);
    return func ? func->start : 0;
}
