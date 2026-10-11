#include "pdb.h"

#include <stdlib.h>
#include <string.h>

#define MSF_MAGIC            "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0"
#define MSF_MAGIC_SIZE       32u
#define MSF_HEADER_SIZE      56u
#define MSF_NIL_STREAM       0xffffffffu

#define PDB_STREAM_INFO      1u
#define PDB_STREAM_DBI       3u
#define PDB_NO_STREAM        0xffffu

#define DBI_HEADER_SIZE      64u
#define DBI_MODULE_FIXED     64u
#define DBI_DEBUG_SECTIONS   5u
#define DBI_MACHINE          58u
#define PE_SECTION_SIZE      40u

#define CV_SIGNATURE_C13     4u
#define DEBUG_S_IGNORE       0x80000000u
#define DEBUG_S_LINES        0xf2u
#define DEBUG_S_FILECHKSMS   0xf4u
#define CV_LINES_COLUMNS     0x0001u
#define CV_LINE_HIDDEN_1     0xfeefeeu
#define CV_LINE_HIDDEN_2     0xf00f00u

#define S_PUB32              0x110eu
#define S_LDATA32            0x110cu
#define S_GDATA32            0x110du
#define CVPSF_CODE           0x1u
#define CVPSF_FUNCTION       0x2u

#define NAMES_SIGNATURE      0xeffeeffeu

static dbg_status corrupt(const pdb_reader *reader, const char *what)
{
    dbg_out(reader->dbg, DBG_OUT_ERROR, "%s: corrupt PDB (%s)\n", reader->module->symbol_file,
            what);
    return DBG_E_BADARG;
}

static uint32_t blocks_for(const msf_file *msf, uint32_t bytes)
{
    return bytes / msf->block_size + (bytes % msf->block_size != 0);
}

static bool block_ok(const msf_file *msf, uint32_t block)
{
    return block < msf->block_count &&
           (size_t)block * msf->block_size + msf->block_size <= msf->size;
}

static uint32_t stream_size(const msf_file *msf, uint32_t index)
{
    uint32_t size;

    size = read_u32(msf->sizes + (size_t)index * 4);
    return size == MSF_NIL_STREAM ? 0 : size;
}

static dbg_status msf_open(pdb_reader *reader, const uint8_t *data, size_t size)
{
    msf_file      *msf;
    const uint8_t *map;
    uint32_t       directory_bytes;
    uint32_t       directory_blocks;
    uint32_t       map_block;
    uint32_t       block;
    uint32_t       index;
    uint32_t       next;
    size_t         list_offset;

    msf = &reader->msf;
    msf->data = data;
    msf->size = size;
    if (size < MSF_HEADER_SIZE || memcmp(data, MSF_MAGIC, MSF_MAGIC_SIZE))
        return corrupt(reader, "MSF header");
    msf->block_size = read_u32(data + 32);
    msf->block_count = read_u32(data + 40);
    directory_bytes = read_u32(data + 44);
    map_block = read_u32(data + 52);
    if (msf->block_size < 512 || msf->block_size > 65536 ||
        (msf->block_size & (msf->block_size - 1)) || !directory_bytes)
        return corrupt(reader, "block size");
    directory_blocks = blocks_for(msf, directory_bytes);
    if (!block_ok(msf, map_block) || (size_t)directory_blocks * 4 > msf->block_size)
        return corrupt(reader, "directory block map");
    map = data + (size_t)map_block * msf->block_size;
    msf->directory = malloc((size_t)directory_blocks * msf->block_size);
    if (!msf->directory)
        return DBG_E_NOMEM;
    for (index = 0; index < directory_blocks; index++) {
        block = read_u32(map + index * 4);
        if (!block_ok(msf, block))
            return corrupt(reader, "directory block");
        memcpy(msf->directory + (size_t)index * msf->block_size,
               data + (size_t)block * msf->block_size, msf->block_size);
    }

    msf->stream_count = read_u32(msf->directory);
    if ((size_t)msf->stream_count * 4 + 4 > directory_bytes)
        return corrupt(reader, "stream count");
    msf->sizes = msf->directory + 4;
    msf->first_block = malloc((msf->stream_count ? msf->stream_count : 1) *
                              sizeof *msf->first_block);
    if (!msf->first_block)
        return DBG_E_NOMEM;
    list_offset = 4 + (size_t)msf->stream_count * 4;
    next = 0;
    for (index = 0; index < msf->stream_count; index++) {
        msf->first_block[index] = next;
        next += blocks_for(msf, stream_size(msf, index));
    }
    if (list_offset + (size_t)next * 4 > directory_bytes)
        return corrupt(reader, "stream block lists");
    return DBG_OK;
}

static void msf_close(msf_file *msf)
{
    free(msf->directory);
    free(msf->first_block);
    msf->directory = NULL;
    msf->first_block = NULL;
}

dbg_status pdb_stream_read(pdb_reader *reader, uint32_t index, pdb_stream *out)
{
    msf_file      *msf;
    const uint8_t *blocks;
    uint32_t       size;
    uint32_t       count;
    uint32_t       block;
    uint32_t       copied;
    uint32_t       chunk;
    uint32_t       slot;

    msf = &reader->msf;
    out->data = NULL;
    out->size = 0;
    if (index >= msf->stream_count)
        return corrupt(reader, "stream index");
    size = stream_size(msf, index);
    count = blocks_for(msf, size);
    blocks = msf->directory + 4 + (size_t)msf->stream_count * 4 +
             (size_t)msf->first_block[index] * 4;
    out->data = malloc(size ? size : 1);
    if (!out->data)
        return DBG_E_NOMEM;
    copied = 0;
    for (slot = 0; slot < count; slot++) {
        block = read_u32(blocks + (size_t)slot * 4);
        if (!block_ok(msf, block)) {
            free(out->data);
            out->data = NULL;
            return corrupt(reader, "stream block");
        }
        chunk = size - copied < msf->block_size ? size - copied : msf->block_size;
        memcpy(out->data + copied, msf->data + (size_t)block * msf->block_size, chunk);
        copied += chunk;
    }
    out->size = size;
    return DBG_OK;
}

static const char *string_in(const pdb_stream *stream, uint32_t offset, uint32_t start,
                             size_t *len)
{
    const char *text;
    const char *end;

    if (offset >= stream->size - start)
        return NULL;
    text = (const char *)stream->data + start + offset;
    end = memchr(text, '\0', stream->size - start - offset);
    if (!end)
        return NULL;
    *len = (size_t)(end - text);
    return text;
}

static dbg_status read_info(pdb_reader *reader, uint32_t *names_index)
{
    pdb_stream     info;
    const uint8_t *cursor;
    const uint8_t *end;
    const uint8_t *entry;
    const char    *buffer;
    uint32_t       buffer_len;
    uint32_t       present_words;
    uint32_t       deleted_words;
    uint32_t       word;
    uint32_t       bit;
    uint32_t       key;
    uint32_t       value;
    dbg_status     status;

    *names_index = 0;
    status = pdb_stream_read(reader, PDB_STREAM_INFO, &info);
    if (status != DBG_OK)
        return status;
    if (info.size < 28 + 4) {
        free(info.data);
        return corrupt(reader, "info stream");
    }
    reader->age = read_u32(info.data + 8);
    memcpy(reader->guid, info.data + 12, sizeof reader->guid);
    cursor = info.data + 28;
    end = info.data + info.size;
    buffer_len = read_u32(cursor);
    cursor += 4;
    if (buffer_len > (size_t)(end - cursor) || (size_t)(end - cursor) - buffer_len < 12) {
        free(info.data);
        return DBG_OK;
    }
    buffer = (const char *)cursor;
    cursor += buffer_len + 8;
    present_words = read_u32(cursor);
    cursor += 4;
    if ((size_t)present_words * 4 + 4 > (size_t)(end - cursor)) {
        free(info.data);
        return DBG_OK;
    }
    deleted_words = read_u32(cursor + (size_t)present_words * 4);
    if ((size_t)(present_words + deleted_words) * 4 + 4 > (size_t)(end - cursor)) {
        free(info.data);
        return DBG_OK;
    }
    entry = cursor + (size_t)(present_words + deleted_words) * 4 + 4;
    for (word = 0; word < present_words; word++) {
        for (bit = 0; bit < 32; bit++) {
            if (!(read_u32(cursor + word * 4) & (1u << bit)))
                continue;
            if ((size_t)(end - entry) < 8)
                break;
            key = read_u32(entry);
            value = read_u32(entry + 4);
            entry += 8;
            if (buffer_len >= 7 && key <= buffer_len - 7 && !memcmp(buffer + key, "/names", 7))
                *names_index = value;
        }
    }
    free(info.data);
    return DBG_OK;
}

static dbg_status read_names(pdb_reader *reader, uint32_t index)
{
    dbg_status status;

    if (!index)
        return DBG_OK;
    status = pdb_stream_read(reader, index, &reader->names);
    if (status != DBG_OK)
        return status;
    if (reader->names.size < 12 || read_u32(reader->names.data) != NAMES_SIGNATURE) {
        free(reader->names.data);
        reader->names.data = NULL;
        reader->names.size = 0;
    }
    return DBG_OK;
}

static const char *name_at(const pdb_reader *reader, uint32_t offset, size_t *len)
{
    uint32_t bytes;

    if (!reader->names.data)
        return NULL;
    bytes = read_u32(reader->names.data + 8);
    if (bytes > reader->names.size - 12 || offset >= bytes)
        return NULL;
    return string_in(&reader->names, offset, 12, len);
}

bool pdb_section_rva(const pdb_reader *reader, uint16_t section, uint32_t offset,
                        uint64_t *rva)
{
    if (!section || section > reader->section_count)
        return false;
    *rva = (uint64_t)reader->section_rvas[section - 1] + offset;
    return true;
}

static dbg_status read_sections(pdb_reader *reader, uint16_t stream_index)
{
    pdb_stream headers;
    uint64_t   end;
    uint32_t   index;
    dbg_status status;

    if (stream_index == PDB_NO_STREAM)
        return corrupt(reader, "no section headers");
    status = pdb_stream_read(reader, stream_index, &headers);
    if (status != DBG_OK)
        return status;
    reader->section_count = headers.size / PE_SECTION_SIZE;
    reader->section_rvas = calloc(reader->section_count ? reader->section_count : 1,
                                  sizeof *reader->section_rvas);
    if (!reader->section_rvas) {
        free(headers.data);
        return DBG_E_NOMEM;
    }
    for (index = 0; index < reader->section_count; index++) {
        reader->section_rvas[index] = read_u32(headers.data + index * PE_SECTION_SIZE + 12);
        end = (uint64_t)reader->section_rvas[index] +
              read_u32(headers.data + index * PE_SECTION_SIZE + 8);
        if (reader->module->pub.base + end > reader->module->pub.end)
            reader->module->pub.end = reader->module->pub.base + end;
    }
    free(headers.data);
    return DBG_OK;
}

static uint32_t checksum_file(pdb_reader *reader, const uint8_t *checksums, uint32_t size,
                              uint32_t entry)
{
    const char *path;
    size_t      len;

    if (entry + 6 > size)
        return UINT32_MAX;
    if (reader->file_cache && entry / 4 < reader->file_cache_size &&
        reader->file_cache[entry / 4] != UINT32_MAX)
        return reader->file_cache[entry / 4];
    path = name_at(reader, read_u32(checksums + entry), &len);
    if (!path)
        return UINT32_MAX;
    if (reader->file_cache && entry / 4 < reader->file_cache_size)
        reader->file_cache[entry / 4] = symbuild_file(&reader->builder, path, len);
    else
        return symbuild_file(&reader->builder, path, len);
    return reader->file_cache[entry / 4];
}

static void read_line_block(pdb_reader *reader, const uint8_t *lines, uint32_t size,
                            const uint8_t *checksums, uint32_t checksums_size)
{
    const uint8_t *block;
    uint64_t       base_rva;
    uint64_t       code_end;
    uint64_t       start;
    uint64_t       end;
    uint32_t       offset;
    uint32_t       count;
    uint32_t       block_size;
    uint32_t       entry_size;
    uint32_t       index;
    uint32_t       number;
    uint32_t       file;
    uint16_t       flags;

    if (size < 12 || !pdb_section_rva(reader, read_u16(lines + 4), read_u32(lines), &base_rva))
        return;
    flags = read_u16(lines + 6);
    code_end = base_rva + read_u32(lines + 8);
    entry_size = flags & CV_LINES_COLUMNS ? 12u : 8u;
    for (offset = 12; offset + 12 <= size; offset += block_size) {
        block = lines + offset;
        count = read_u32(block + 4);
        block_size = read_u32(block + 8);
        if (block_size < 12 || block_size > size - offset ||
            (uint64_t)count * entry_size > block_size - 12)
            return;
        file = checksum_file(reader, checksums, checksums_size, read_u32(block));
        if (file == UINT32_MAX)
            continue;
        for (index = 0; index < count; index++) {
            start = base_rva + read_u32(block + 12 + index * 8);
            end = index + 1 < count ? base_rva + read_u32(block + 12 + (index + 1) * 8)
                                    : code_end;
            number = read_u32(block + 12 + index * 8 + 4) & 0xffffffu;
            if (number == CV_LINE_HIDDEN_1 || number == CV_LINE_HIDDEN_2)
                continue;
            symbuild_line(&reader->builder, reader->module->pub.base + start,
                          reader->module->pub.base + end, number, file);
        }
    }
}

static void read_c13(pdb_reader *reader, const uint8_t *data, uint32_t size)
{
    const uint8_t *checksums;
    uint32_t       checksums_size;
    uint32_t       offset;
    uint32_t       kind;
    uint32_t       length;

    checksums = NULL;
    checksums_size = 0;
    for (offset = 0; offset + 8 <= size; offset += 8 + ((length + 3) & ~3u)) {
        kind = read_u32(data + offset) & ~DEBUG_S_IGNORE;
        length = read_u32(data + offset + 4);
        if (length > size - offset - 8)
            return;
        if (kind == DEBUG_S_FILECHKSMS) {
            checksums = data + offset + 8;
            checksums_size = length;
        }
    }
    if (!checksums)
        return;
    reader->file_cache_size = checksums_size / 4 + 1;
    reader->file_cache = malloc((size_t)reader->file_cache_size * sizeof *reader->file_cache);
    if (reader->file_cache)
        memset(reader->file_cache, 0xff,
               (size_t)reader->file_cache_size * sizeof *reader->file_cache);
    for (offset = 0; offset + 8 <= size; offset += 8 + ((length + 3) & ~3u)) {
        kind = read_u32(data + offset) & ~DEBUG_S_IGNORE;
        length = read_u32(data + offset + 4);
        if (length > size - offset - 8)
            break;
        if (kind == DEBUG_S_LINES)
            read_line_block(reader, data + offset + 8, length, checksums, checksums_size);
    }
    free(reader->file_cache);
    reader->file_cache = NULL;
    reader->file_cache_size = 0;
}

static dbg_status read_module(pdb_reader *reader, const uint8_t *info)
{
    pdb_stream stream;
    uint32_t   symbols_size;
    uint32_t   c11_size;
    uint32_t   c13_size;
    uint16_t   index;
    dbg_status status;

    index = read_u16(info + 34);
    symbols_size = read_u32(info + 36);
    c11_size = read_u32(info + 40);
    c13_size = read_u32(info + 44);
    if (index == PDB_NO_STREAM)
        return DBG_OK;
    status = pdb_stream_read(reader, index, &stream);
    if (status != DBG_OK)
        return status;
    if (symbols_size > stream.size || c11_size > stream.size - symbols_size ||
        c13_size > stream.size - symbols_size - c11_size) {
        free(stream.data);
        return DBG_OK;
    }
    if (symbols_size >= 4 && read_u32(stream.data) == CV_SIGNATURE_C13)
        pdb_module_symbols(reader, stream.data + 4, symbols_size - 4);
    read_c13(reader, stream.data + symbols_size + c11_size, c13_size);
    free(stream.data);
    return reader->builder.status;
}

static void read_globals(pdb_reader *reader, uint16_t stream_index)
{
    pdb_stream     records;
    const uint8_t *record;
    const char    *name;
    const char    *name_end;
    uint32_t       offset;
    uint16_t       length;
    uint16_t       kind;
    uint64_t       rva;

    if (stream_index == PDB_NO_STREAM || pdb_stream_read(reader, stream_index, &records) != DBG_OK)
        return;
    for (offset = 0; offset + 4 <= records.size; offset += length + 2) {
        record = records.data + offset;
        length = read_u16(record);
        kind = read_u16(record + 2);
        if (length < 2 || length > records.size - offset - 2)
            break;
        if (kind == S_GDATA32 || kind == S_LDATA32)
            pdb_global_data(reader, record + 4, kind, length - 2u);
        if (kind != S_PUB32 || length < 2 + 10)
            continue;
        if (!(read_u32(record + 4) & (CVPSF_CODE | CVPSF_FUNCTION)))
            continue;
        if (!pdb_section_rva(reader, read_u16(record + 12), read_u32(record + 8), &rva))
            continue;
        name = (const char *)record + 14;
        name_end = memchr(name, '\0', (size_t)(length + 2) - 14);
        if (name_end)
            symbuild_func(&reader->builder, reader->module->pub.base + rva, 0, name,
                          (size_t)(name_end - name));
    }
    free(records.data);
}

static dbg_status read_dbi(pdb_reader *reader)
{
    pdb_stream     dbi;
    const uint8_t *modules;
    const uint8_t *debug_header;
    uint32_t       module_size;
    uint32_t       offset;
    uint32_t       entry_end;
    uint32_t       skip;
    uint32_t       debug_size;
    uint16_t       symbols_stream;
    const char    *text;
    dbg_status     status;

    status = pdb_stream_read(reader, PDB_STREAM_DBI, &dbi);
    if (status != DBG_OK)
        return status;
    if (!dbi.size) {
        free(dbi.data);
        dbg_out(reader->dbg, DBG_OUT_ERROR,
                "%s: no debug info stream: a compiler PDB (like vc140.pdb), not the PDB of a "
                "linked image\n", reader->module->symbol_file);
        return DBG_E_BADARG;
    }
    if (dbi.size < DBI_HEADER_SIZE) {
        free(dbi.data);
        return corrupt(reader, "DBI header");
    }
    symbols_stream = read_u16(dbi.data + 20);
    reader->machine = read_u16(dbi.data + DBI_MACHINE);
    module_size = read_u32(dbi.data + 24);
    skip = read_u32(dbi.data + 28) + read_u32(dbi.data + 32) + read_u32(dbi.data + 36) +
           read_u32(dbi.data + 40) + read_u32(dbi.data + 52);
    debug_size = read_u32(dbi.data + 48);
    if (module_size > dbi.size - DBI_HEADER_SIZE ||
        skip > dbi.size - DBI_HEADER_SIZE - module_size ||
        debug_size > dbi.size - DBI_HEADER_SIZE - module_size - skip ||
        debug_size < (DBI_DEBUG_SECTIONS + 1) * 2) {
        free(dbi.data);
        return corrupt(reader, "DBI substreams");
    }
    modules = dbi.data + DBI_HEADER_SIZE;
    debug_header = modules + module_size + skip;
    status = read_sections(reader, read_u16(debug_header + DBI_DEBUG_SECTIONS * 2));

    for (offset = 0; status == DBG_OK && offset + DBI_MODULE_FIXED < module_size;
         offset = (entry_end + 3) & ~3u) {
        text = memchr(modules + offset + DBI_MODULE_FIXED, '\0',
                      module_size - offset - DBI_MODULE_FIXED);
        if (!text)
            break;
        text = memchr(text + 1, '\0', (size_t)(modules + module_size - (const uint8_t *)text - 1));
        if (!text)
            break;
        entry_end = (uint32_t)((const uint8_t *)text + 1 - modules);
        status = read_module(reader, modules + offset);
    }
    if (status == DBG_OK)
        read_globals(reader, symbols_stream);
    free(dbi.data);
    return status == DBG_OK ? reader->builder.status : status;
}

dbg_status pdb_parse(dbg_ctx *dbg, sym_module *module, const uint8_t *data, size_t size)
{
    pdb_reader reader;
    uint32_t   names_index;
    dbg_status status;

    memset(&reader, 0, sizeof reader);
    reader.dbg = dbg;
    reader.module = module;
    module->pub.end = module->pub.base;
    symbuild_init(&reader.builder, module);
    status = msf_open(&reader, data, size);
    if (status == DBG_OK)
        status = read_info(&reader, &names_index);
    if (status == DBG_OK)
        status = read_names(&reader, names_index);
    if (status == DBG_OK)
        status = pdb_types_open(&reader);
    if (status == DBG_OK)
        status = read_dbi(&reader);
    if (status == DBG_OK)
        pdb_types_finish(&reader);
    if (status == DBG_OK)
        status = reader.builder.status;
    if (status == DBG_OK)
        status = symbuild_finish(&reader.builder);
    else
        symbuild_free(&reader.builder);
    if (status == DBG_OK) {
        memcpy(module->pdb_guid, reader.guid, sizeof module->pdb_guid);
        module->pdb_age = reader.age;
        module->has_pdb_id = true;
    }
    msf_close(&reader.msf);
    free(reader.names.data);
    free(reader.section_rvas);
    pdb_types_close(&reader);
    return status;
}
