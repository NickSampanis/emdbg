#ifndef DBGENG_PDB_H
#define DBGENG_PDB_H

#include <stddef.h>
#include <stdint.h>

#include "dbg.h"

#define PDB_MACHINE_X86   0x014cu

typedef struct msf_file {
    const uint8_t *data;
    size_t         size;
    uint32_t       block_size;
    uint32_t       block_count;
    uint8_t       *directory;
    uint32_t       stream_count;
    const uint8_t *sizes;
    uint32_t      *first_block;
} msf_file;

typedef struct pdb_stream {
    uint8_t *data;
    uint32_t size;
} pdb_stream;

typedef struct pdb_name_slot {
    const char *key;
    uint32_t    len;
    uint32_t    type;
} pdb_name_slot;

typedef struct pdb_types {
    pdb_stream     stream;
    uint32_t       first;
    uint32_t       count;
    uint32_t      *offsets;
    uint32_t      *map;
    uint32_t      *simple;
    pdb_name_slot *names;
    uint32_t       name_cap;
    bool           names_built;
    uint32_t      *pending;
    uint32_t       pending_count;
    uint32_t       pending_cap;
} pdb_types;

typedef struct pdb_reader {
    dbg_ctx     *dbg;
    sym_module  *module;
    msf_file     msf;
    sym_builder  builder;
    uint32_t    *section_rvas;
    uint32_t     section_count;
    pdb_stream   names;
    uint8_t      guid[16];
    uint32_t     age;
    uint16_t     machine;
    uint32_t    *file_cache;
    uint32_t     file_cache_size;
    pdb_types    types;
} pdb_reader;

static inline uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)(bytes[0] | bytes[1] << 8);
}

static inline uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

dbg_status pdb_stream_read(pdb_reader *reader, uint32_t index, pdb_stream *out);
bool       pdb_section_rva(const pdb_reader *reader, uint16_t section, uint32_t offset,
                           uint64_t *rva);
uint32_t   pdb_numeric(const uint8_t *data, uint32_t len, int64_t *value);
bool       pdb_name(const uint8_t *data, uint32_t len, const char **text, size_t *text_len);

dbg_status pdb_types_open(pdb_reader *reader);
uint32_t   pdb_type(pdb_reader *reader, uint32_t index);
void       pdb_types_finish(pdb_reader *reader);
void       pdb_types_close(pdb_reader *reader);

void pdb_module_symbols(pdb_reader *reader, const uint8_t *symbols, uint32_t size);
void pdb_global_data(pdb_reader *reader, const uint8_t *record, uint16_t kind, uint32_t len);

#endif
