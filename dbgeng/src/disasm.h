#ifndef DBGENG_DISASM_H
#define DBGENG_DISASM_H

#include <stdbool.h>
#include <stdint.h>

#include "emdbg/dbgeng.h"

bool disasm_decode(dbg_cpu_mode mode, uint64_t addr, const uint8_t *buf, uint32_t len,
                   dbg_insn *out, bool *step_over);

#define EPILOG_MAX_POPS 16

typedef struct epilog_info {
    const char *base;
    int64_t     cfa_offset;
    uint32_t    pop_count;
    const char *pops[EPILOG_MAX_POPS];
    int64_t     pop_offsets[EPILOG_MAX_POPS];
} epilog_info;

bool     disasm_epilog(const uint8_t *code, uint32_t len, epilog_info *out);

uint32_t disasm_address_mask(dbg_cpu_mode mode, const uint8_t *buf, uint32_t len,
                             uint8_t *wildcard, uint8_t *starts);

#endif
