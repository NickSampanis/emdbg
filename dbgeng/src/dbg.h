#ifndef DBGENG_DBG_H
#define DBGENG_DBG_H

#include <stdbool.h>
#include <stdint.h>

#include "emdbg/dbgeng.h"
#include "link.h"

#define DBG_CALL_TIMEOUT_MS  5000u
#define DBG_WAIT_STOP_MS     1000u

typedef enum bp_impl {
    BP_IMPL_STUB,
    BP_IMPL_SOFT,
    BP_IMPL_DR,
} bp_impl;

typedef struct bp_entry {
    dbg_bp    pub;
    bool      warned;
    uint8_t   impl;
    uint8_t   dr;
    uint8_t   orig;
} bp_entry;

typedef struct sym_line {
    uint64_t start;
    uint64_t end;
    uint32_t line;
    uint32_t file;
} sym_line;

struct reg_def;

typedef enum sym_type_kind {
    SYM_TYPE_NONE,
    SYM_TYPE_VOID,
    SYM_TYPE_BOOL,
    SYM_TYPE_INT,
    SYM_TYPE_UINT,
    SYM_TYPE_FLOAT,
    SYM_TYPE_POINTER,
    SYM_TYPE_ARRAY,
    SYM_TYPE_STRUCT,
    SYM_TYPE_UNION,
    SYM_TYPE_ENUM,
    SYM_TYPE_FUNCTION,
    SYM_TYPE_TYPEDEF,
} sym_type_kind;

enum {
    SYM_TYPE_CONST    = 1 << 0,
    SYM_TYPE_VOLATILE = 1 << 1,
    SYM_TYPE_CHAR     = 1 << 2,
    SYM_TYPE_FORWARD  = 1 << 3,
    SYM_TYPE_VARARGS  = 1 << 4,
};

typedef struct sym_type {
    uint8_t     kind;
    uint8_t     flags;
    uint32_t    size;
    const char *name;
    uint32_t    target;
    uint32_t    count;
    uint32_t    first_member;
    uint32_t    member_count;
} sym_type;

typedef struct sym_member {
    const char *name;
    uint32_t    type;
    uint64_t    offset;
    uint16_t    bit_offset;
    uint16_t    bit_size;
} sym_member;

typedef struct sym_enumerator {
    const char *name;
    int64_t     value;
} sym_enumerator;

typedef enum sym_loc_kind {
    SYM_LOC_NONE,
    SYM_LOC_ABSOLUTE,
    SYM_LOC_CFA,
    SYM_LOC_REG_RELATIVE,
    SYM_LOC_REGISTER,
    SYM_LOC_VALUE,
} sym_loc_kind;

enum {
    SYM_VAR_PARAM  = 1 << 0,
    SYM_VAR_LOCAL  = 1 << 1,
    SYM_VAR_GLOBAL = 1 << 2,
    SYM_VAR_STATIC = 1 << 3,
};

typedef struct sym_location {
    uint8_t               kind;
    const struct reg_def *reg;
    int64_t               offset;
    uint64_t              start;
    uint64_t              end;
} sym_location;

typedef struct sym_var {
    const char *name;
    uint32_t    type;
    uint32_t    flags;
    uint32_t    first_loc;
    uint32_t    loc_count;
    uint64_t    scope_start;
    uint64_t    scope_end;
} sym_var;

typedef struct sym_cfa {
    uint64_t              start;
    const struct reg_def *reg;
    int64_t               offset;
} sym_cfa;

typedef struct sym_func {
    uint64_t    start;
    uint64_t    end;
    const char *name;
    uint32_t    type;
    uint32_t    first_var;
    uint32_t    var_count;
    uint32_t    first_cfa;
    uint32_t    cfa_count;
} sym_func;

typedef struct sym_file {
    char            *path;
    char            *resolved;
    bool             searched;
    const sym_line **by_line;
    uint32_t         by_line_count;
} sym_file;

typedef struct sym_module {
    dbg_module       pub;
    char            *name;
    char            *symbol_file;
    char            *names;
    sym_func        *funcs;
    sym_line        *lines;
    sym_file        *files;
    uint32_t         file_count;
    const sym_func **by_name;
    const sym_var  **globals_by_name;
    char            *strings;
    sym_type        *types;
    sym_member      *members;
    sym_enumerator  *enumerators;
    sym_var         *vars;
    sym_var         *globals;
    sym_location    *locations;
    sym_cfa         *cfas;
    uint32_t         member_count;
    uint32_t         enumerator_count;
    uint32_t         var_count;
    uint32_t         location_count;
    uint32_t         cfa_count;
    uint8_t          pdb_guid[16];
    uint32_t         pdb_age;
    bool             has_pdb_id;
} sym_module;

typedef struct build_func {
    uint64_t start;
    uint64_t end;
    uint32_t name;
    uint32_t first_var;
    uint32_t var_count;
} build_func;

typedef struct build_type {
    uint8_t  kind;
    uint8_t  flags;
    uint32_t size;
    uint32_t name;
    uint32_t target;
    uint32_t count;
    uint32_t first_member;
    uint32_t member_count;
} build_type;

typedef struct build_member {
    uint32_t name;
    uint32_t type;
    uint64_t offset;
    uint16_t bit_offset;
    uint16_t bit_size;
} build_member;

typedef struct build_enum {
    uint32_t name;
    int64_t  value;
} build_enum;

typedef struct build_var {
    uint32_t name;
    uint32_t type;
    uint32_t flags;
    uint32_t first_loc;
    uint32_t loc_count;
    uint64_t scope_start;
    uint64_t scope_end;
} build_var;

typedef struct sym_builder {
    sym_module   *module;
    dbg_status    status;
    char         *strings;
    size_t        string_len;
    size_t        string_cap;
    uint32_t     *slots;
    uint32_t      slot_cap;
    uint32_t      slot_used;
    build_func   *funcs;
    uint32_t      func_count;
    uint32_t      func_cap;
    uint32_t     *files;
    uint32_t      file_count;
    uint32_t      file_cap;
    sym_line     *lines;
    uint32_t      line_count;
    uint32_t      line_cap;
    build_type   *types;
    uint32_t      type_count;
    uint32_t      type_cap;
    build_member *members;
    uint32_t      member_count;
    uint32_t      member_cap;
    build_enum   *enums;
    uint32_t      enum_count;
    uint32_t      enum_cap;
    build_var    *vars;
    uint32_t      var_count;
    uint32_t      var_cap;
    build_var    *globals;
    uint32_t      global_count;
    uint32_t      global_cap;
    sym_location *locations;
    uint32_t      location_count;
    uint32_t      location_cap;
} sym_builder;

#define UNWIND_NO_IMAGE_SLOTS 16
#define UNWIND_GPRS           16
#define UNWIND_GPR_SP         4
#define UNWIND_MAX_SAVES      16

typedef struct unwind_save {
    uint8_t reg;
    uint8_t base;
    int64_t offset;
} unwind_save;

typedef struct unwind_result {
    uint8_t     base;
    int64_t     offset;
    uint32_t    save_count;
    unwind_save saves[UNWIND_MAX_SAVES];
} unwind_result;

typedef struct pdata_image {
    uint64_t base;
    uint64_t end;
    uint64_t fingerprint;
    uint8_t *table;
    uint32_t count;
    uint32_t generation;
} pdata_image;

typedef struct sym_line_info {
    const sym_module *module;
    uint32_t          file;
    uint32_t          line;
    uint64_t          start;
    uint64_t          end;
} sym_line_info;

typedef enum plan_kind {
    PLAN_NONE,
    PLAN_LINE,
    PLAN_TO_CALL,
    PLAN_TO_BRANCH,
} plan_kind;

typedef enum plan_wait {
    WAIT_NONE,
    WAIT_TARGET,
    WAIT_RETURN,
} plan_wait;

typedef enum plan_result {
    PLAN_LOOP,
    PLAN_RESUMED,
    PLAN_FINISHED,
    PLAN_INTERRUPTED,
    PLAN_FAILED,
} plan_result;

typedef struct step_plan {
    uint8_t       kind;
    uint8_t       wait;
    bool          into;
    bool          skip_first;
    bool          in_gap;
    uint64_t      target;
    uint64_t      return_sp;
    uint64_t      func_start;
    sym_line_info line;
    uint32_t      steps;
    dbg_status    status;
} step_plan;

struct dbg_ctx {
    dbg_callbacks cb;
    dbg_state     state;
    dbg_link      link;

    em_hello_rep  target;
    bool          have_target;

    bool          stop_raw;

    uint16_t      cpu;
    em_stopped    last_stop;
    em_x86_regs   regs;
    dbg_cpu_mode  mode;

    bp_entry     *bps;
    int           bp_count;
    int           bp_cap;
    uint32_t      next_bp_id;
    bp_entry      temp_bp;
    int           soft_planted;
    uint32_t      lifted_id;
    bool          stop_landed;
    bool          force_soft_bp;
    uint64_t      step_out_sp;
    uint32_t      frame_index;
    bool          temp_hit;
    bool          source_step;
    step_plan     plan;

    uint32_t      stop_generation;
    pdata_image  *pdata;
    uint32_t      pdata_count;
    uint64_t      no_image[UNWIND_NO_IMAGE_SLOTS];
    uint32_t      no_image_count;
    uint32_t      no_image_generation;

    uint8_t      *scratch;

    sym_module   *modules;
    int           module_count;
    char         *sym_path;
    char         *src_path;
    char         *exe_path;

    const char   *repeat;
    uint64_t      next_dump;
    bool          have_next_dump;
    uint64_t      next_unasm;
    bool          have_next_unasm;
};

void       dbg_out(dbg_ctx *dbg, dbg_out_kind kind, const char *fmt, ...);

dbg_status dbg_put_regs(dbg_ctx *dbg, uint32_t block);

dbg_status mem_read_raw(dbg_ctx *dbg, uint8_t space, uint64_t addr, void *buf, uint32_t len,
                        uint32_t *done);
dbg_status mem_write_raw(dbg_ctx *dbg, uint8_t space, uint64_t addr, const void *buf,
                         uint32_t len);
dbg_status regs_put_raw(dbg_ctx *dbg, uint32_t block);

dbg_status step_raw(dbg_ctx *dbg);
dbg_status resume_raw(dbg_ctx *dbg);

dbg_status dbg_finish(dbg_ctx *dbg, dbg_status status);

dbg_status bp_plant(dbg_ctx *dbg, bp_entry *entry);
dbg_status bp_unplant(dbg_ctx *dbg, bp_entry *entry);

bp_entry  *bp_exec_at(dbg_ctx *dbg, uint64_t addr);
bp_entry  *bp_by_id(dbg_ctx *dbg, uint32_t id);

void       bp_hide(const dbg_ctx *dbg, uint64_t addr, uint8_t *buf, uint32_t len);
void       bp_mask_write(dbg_ctx *dbg, uint64_t addr, uint8_t *buf, uint32_t len);

void       bp_plant_pending(dbg_ctx *dbg);
void       bp_unplant_all(dbg_ctx *dbg);
void       bp_forget_planted(dbg_ctx *dbg);

bool       bp_on_stop(dbg_ctx *dbg);
dbg_status bp_step_out_resume(dbg_ctx *dbg);
void       bp_step_out_abort(dbg_ctx *dbg);

dbg_status bp_step_off(dbg_ctx *dbg, bool *stepped);

void       sym_free_all(dbg_ctx *dbg);

bool       paging_enabled(const dbg_ctx *dbg);

uint8_t   *sym_read_file(const char *path, size_t *size);

dbg_status ids_parse_v2(dbg_ctx *dbg, sym_module *module, const uint8_t *data, size_t size);
dbg_status pdb_parse(dbg_ctx *dbg, sym_module *module, const uint8_t *data, size_t size);
bool       image_pdb_id(dbg_ctx *dbg, uint64_t base, uint8_t *guid, uint32_t *age);
bool       image_locate(dbg_ctx *dbg, uint64_t addr, uint64_t *base);

bool       unwind_rule(dbg_ctx *dbg, uint64_t pc, uint64_t lookup, unwind_result *out);
int        unwind_gpr(const char *name, uint8_t *shift, uint8_t *size);
void       unwind_forget(dbg_ctx *dbg);

void       symbuild_init(sym_builder *builder, sym_module *module);
uint32_t   symbuild_string(sym_builder *builder, const char *text, size_t len);
uint32_t   symbuild_func(sym_builder *builder, uint64_t start, uint64_t end, const char *name,
                         size_t len);
void       symbuild_func_vars(sym_builder *builder, uint32_t func, uint32_t first,
                              uint32_t count);
uint32_t   symbuild_type(sym_builder *builder, const build_type *type);
void       symbuild_type_set(sym_builder *builder, uint32_t index, const build_type *type);
uint32_t   symbuild_member(sym_builder *builder, const build_member *member);
uint32_t   symbuild_enum(sym_builder *builder, const build_enum *value);
uint32_t   symbuild_location(sym_builder *builder, const sym_location *location);
uint32_t   symbuild_var(sym_builder *builder, bool global, const build_var *var);
uint32_t   symbuild_file(sym_builder *builder, const char *path, size_t len);
void       symbuild_line(sym_builder *builder, uint64_t start, uint64_t end, uint32_t line,
                         uint32_t file);
dbg_status symbuild_finish(sym_builder *builder);
void       symbuild_free(sym_builder *builder);

bool            sym_frame_cfa(dbg_ctx *dbg, uint64_t *cfa);
bool            sym_line_at(dbg_ctx *dbg, uint64_t addr, sym_line_info *out);
uint64_t        sym_func_start(dbg_ctx *dbg, uint64_t addr);

void            dbg_emit(dbg_ctx *dbg, dbg_event_kind kind);
void            dbg_settle(dbg_ctx *dbg, uint32_t timeout_ms);
uint64_t        dbg_stack_pointer(const dbg_ctx *dbg);

dbg_status      bp_temp_plant(dbg_ctx *dbg, uint64_t addr);
dbg_status      bp_lift_at(dbg_ctx *dbg, uint64_t pc);

plan_result     step_plan_on_stop(dbg_ctx *dbg);
void            step_plan_cancel(dbg_ctx *dbg);

sym_module     *sym_module_at(dbg_ctx *dbg, uint64_t addr);
const sym_func *sym_func_in(const sym_module *module, uint64_t addr);

#endif
