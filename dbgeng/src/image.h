#ifndef DBGENG_IMAGE_H
#define DBGENG_IMAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dbg.h"

#define IMAGE_PATTERN_SIZE 16u

typedef struct image_pattern {
    uint32_t rva;
    uint8_t  bytes[IMAGE_PATTERN_SIZE];
} image_pattern;

typedef struct image_match {
    uint64_t offset;
    uint32_t rva;
    uint32_t alignment;
} image_match;

typedef struct byte_pattern {
    const uint8_t *bytes;
    const uint8_t *wildcard;
    uint32_t       len;
} byte_pattern;

int        image_match_bytes(const uint8_t *data, size_t size, const byte_pattern *pattern,
                             image_match *matches, int max);

#define IMAGE_MAX_NOTES 4

typedef struct image_header {
    dbg_image_format format;
    uint64_t         base_delta;
    uint64_t         size;
    uint32_t         debug_rva;
    uint32_t         debug_size;
    uint32_t         exception_rva;
    uint32_t         exception_size;
    uint64_t         fingerprint;
    uint32_t         note_count;
    uint64_t         note_vaddr[IMAGE_MAX_NOTES];
    uint64_t         note_size[IMAGE_MAX_NOTES];
} image_header;

bool       image_parse_header(const uint8_t *data, size_t size, image_header *header);
bool       image_debug_record(const uint8_t *entries, size_t size, uint32_t *record_rva,
                              uint32_t *record_size);
bool       image_codeview_path(const uint8_t *record, size_t size, char *path, size_t cap);
bool       image_build_id(const uint8_t *notes, size_t size, uint8_t *id, uint32_t cap,
                          uint32_t *id_len);

dbg_status image_find_patterns(dbg_ctx *dbg, const char *path, const uint8_t *data, size_t size,
                               const sym_module *module, image_pattern *patterns);

#endif
