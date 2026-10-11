#ifndef DBGENG_CMD_H
#define DBGENG_CMD_H

#include <stddef.h>
#include <stdint.h>

#include "dbg.h"

typedef struct cmd_args {
    const char *line;
    const char *cursor;
    const char *err_at;
    char        err[160];
} cmd_args;

dbg_status cmd_fail(cmd_args *args, const char *at, const char *fmt, ...);

void       cmd_skip_ws(cmd_args *args);
int        cmd_at_end(cmd_args *args);

dbg_status expr_eval(dbg_ctx *dbg, cmd_args *args, uint64_t *out);

typedef struct reg_def {
    const char *name;
    uint8_t     block;
    uint8_t     size;
    uint16_t    offset;
} reg_def;

const reg_def *reg_find(const char *name, size_t len);

dbg_status     value_dx(dbg_ctx *dbg, cmd_args *args);
dbg_status     value_dv(dbg_ctx *dbg);
uint64_t       reg_get(const em_x86_regs *regs, const reg_def *reg);
void           reg_set(em_x86_regs *regs, const reg_def *reg, uint64_t value);

#endif
