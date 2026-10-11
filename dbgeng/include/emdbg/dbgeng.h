#ifndef EMDBG_DBGENG_H
#define EMDBG_DBGENG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "emstub/proto.h"
#include "emstub/regs_x86.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dbg_ctx dbg_ctx;

typedef enum dbg_status {
    DBG_OK = 0,
    DBG_E_NOMEM,
    DBG_E_CONNECT,
    DBG_E_DISCONNECTED,
    DBG_E_PROTOCOL,
    DBG_E_TIMEOUT,
    DBG_E_RUNNING,
    DBG_E_UNSUPPORTED,
    DBG_E_BADARG,
    DBG_E_FAULT,
    DBG_E_PARTIAL,
} dbg_status;

typedef enum dbg_state {
    DBG_STATE_DISCONNECTED,
    DBG_STATE_RUNNING,
    DBG_STATE_STOPPED,
} dbg_state;

typedef enum dbg_out_kind {
    DBG_OUT_NORMAL,
    DBG_OUT_ECHO,
    DBG_OUT_ERROR,
    DBG_OUT_TARGET,
} dbg_out_kind;

typedef enum dbg_event_kind {
    DBG_EV_CONNECTED,
    DBG_EV_DISCONNECTED,
    DBG_EV_RUNNING,
    DBG_EV_STOPPED,
} dbg_event_kind;

typedef struct dbg_event {
    dbg_event_kind kind;
    uint16_t       cpu;
    em_stop_reason reason;
    uint32_t       bp_id;
    uint64_t       addr;
    uint64_t       pc;
} dbg_event;

typedef struct dbg_callbacks {
    void (*output)(void *user, dbg_out_kind kind, const char *text);
    void (*event)(void *user, const dbg_event *event);
    void  *user;
} dbg_callbacks;

const char *dbg_status_str(dbg_status status);

dbg_ctx    *dbg_create(const dbg_callbacks *callbacks);
void        dbg_destroy(dbg_ctx *dbg);

dbg_status  dbg_connect(dbg_ctx *dbg, const char *host, uint16_t port);
void        dbg_disconnect(dbg_ctx *dbg);

void        dbg_poll(dbg_ctx *dbg);

dbg_state   dbg_get_state(const dbg_ctx *dbg);

const em_hello_rep *dbg_target(const dbg_ctx *dbg);
bool        dbg_target_supports(const dbg_ctx *dbg, em_cmd cmd);

uint16_t    dbg_current_cpu(const dbg_ctx *dbg);

const em_x86_regs *dbg_regs(const dbg_ctx *dbg);

dbg_status  dbg_fetch_regs(dbg_ctx *dbg, uint32_t blocks);

dbg_status  dbg_read_mem(dbg_ctx *dbg, uint8_t space, uint64_t addr, void *buf, uint32_t len,
                         uint32_t *done);
dbg_status  dbg_write_mem(dbg_ctx *dbg, uint8_t space, uint64_t addr, const void *buf,
                          uint32_t len, uint32_t *done);

dbg_status  dbg_continue(dbg_ctx *dbg);
dbg_status  dbg_step(dbg_ctx *dbg);
dbg_status  dbg_pause(dbg_ctx *dbg);

typedef enum dbg_cpu_mode {
    DBG_MODE_REAL16,
    DBG_MODE_PROT16,
    DBG_MODE_PROT32,
    DBG_MODE_LONG64,
} dbg_cpu_mode;

typedef enum dbg_flow {
    DBG_FLOW_NONE,
    DBG_FLOW_JMP,
    DBG_FLOW_JCC,
    DBG_FLOW_CALL,
    DBG_FLOW_RET,
    DBG_FLOW_INT,
    DBG_FLOW_SYSCALL,
} dbg_flow;

#define DBG_INSN_TEXT 96

typedef struct dbg_insn {
    uint64_t addr;
    uint64_t target;
    uint8_t  len;
    uint8_t  bytes[15];
    uint8_t  flow;
    bool     valid;
    bool     has_target;
    char     text[DBG_INSN_TEXT];
} dbg_insn;

dbg_cpu_mode dbg_get_cpu_mode(const dbg_ctx *dbg);

uint64_t    dbg_pc(const dbg_ctx *dbg);

dbg_status  dbg_disasm(dbg_ctx *dbg, uint64_t addr, dbg_insn *out, uint32_t max,
                       uint32_t *count);

dbg_status  dbg_step_over(dbg_ctx *dbg);
dbg_status  dbg_step_out(dbg_ctx *dbg);
dbg_status  dbg_step_line(dbg_ctx *dbg, bool into);
dbg_status  dbg_step_to_call(dbg_ctx *dbg);
dbg_status  dbg_step_to_branch(dbg_ctx *dbg);
void        dbg_set_source_step(dbg_ctx *dbg, bool on);
bool        dbg_get_source_step(const dbg_ctx *dbg);

typedef struct dbg_bp {
    uint32_t id;
    uint64_t addr;
    uint8_t  type;
    uint8_t  len;
    bool     enabled;
    bool     planted;
    uint32_t hits;
} dbg_bp;

dbg_status    dbg_bp_add(dbg_ctx *dbg, uint8_t type, uint64_t addr, uint8_t len, uint32_t *id);
dbg_status    dbg_bp_remove(dbg_ctx *dbg, uint32_t id);
dbg_status    dbg_bp_enable(dbg_ctx *dbg, uint32_t id, bool enable);

int           dbg_bp_count(const dbg_ctx *dbg);
const dbg_bp *dbg_bp_get(const dbg_ctx *dbg, int index);
const dbg_bp *dbg_bp_find(const dbg_ctx *dbg, uint64_t addr);
const char   *dbg_bp_where(const dbg_ctx *dbg, uint32_t id);

dbg_status  dbg_translate(dbg_ctx *dbg, uint64_t va, uint64_t *pa, uint32_t *flags);

dbg_status  dbg_monitor(dbg_ctx *dbg, const char *cmd);

dbg_status  dbg_exec(dbg_ctx *dbg, const char *line);

typedef struct dbg_module {
    const char *name;
    const char *symbol_file;
    uint64_t    base;
    uint64_t    end;
    uint32_t    function_count;
    uint32_t    line_count;
    uint32_t    type_count;
    uint32_t    global_count;
} dbg_module;

typedef struct dbg_symbol {
    const char *module;
    const char *function;
    uint64_t    offset;
} dbg_symbol;

typedef struct dbg_source {
    const char *module;
    const char *function;
    const char *file;
    bool        file_found;
    uint32_t    line;
    uint64_t    start;
    uint64_t    end;
} dbg_source;

dbg_status        dbg_set_sym_path(dbg_ctx *dbg, const char *dirs);
dbg_status        dbg_set_src_path(dbg_ctx *dbg, const char *dirs);
const char       *dbg_get_sym_path(const dbg_ctx *dbg);
const char       *dbg_get_src_path(const dbg_ctx *dbg);
dbg_status        dbg_set_exe_path(dbg_ctx *dbg, const char *dirs);
const char       *dbg_get_exe_path(const dbg_ctx *dbg);

dbg_status        dbg_sym_load(dbg_ctx *dbg, const char *file, uint64_t base);
dbg_status        dbg_sym_scan(dbg_ctx *dbg, const char *file, uint64_t start, uint64_t end);

int               dbg_module_count(const dbg_ctx *dbg);
const dbg_module *dbg_module_get(const dbg_ctx *dbg, int index);

bool        dbg_sym_name(const dbg_ctx *dbg, uint64_t addr, dbg_symbol *out);
bool        dbg_sym_format(const dbg_ctx *dbg, uint64_t addr, char *buf, size_t cap);
bool        dbg_sym_addr(const dbg_ctx *dbg, const char *name, size_t len, uint64_t *addr);

typedef bool (*dbg_sym_fn)(void *user, const char *module, const char *name, uint64_t addr);

int         dbg_sym_enum(const dbg_ctx *dbg, const char *pattern, dbg_sym_fn fn, void *user);

#define DBG_FIND_PATH 512

typedef struct dbg_find_match {
    char     file[DBG_FIND_PATH];
    uint64_t offset;
    uint32_t rva;
    uint64_t base;
    bool     is_pe;
    bool     aligned;
} dbg_find_match;

dbg_status  dbg_find(dbg_ctx *dbg, uint64_t addr, uint32_t len, const char *extension,
                     const char *dirs, dbg_find_match *matches, int max, int *count,
                     int *files_searched);

typedef enum dbg_image_format {
    DBG_IMAGE_NONE,
    DBG_IMAGE_PE,
    DBG_IMAGE_TE,
    DBG_IMAGE_ELF,
} dbg_image_format;

typedef struct dbg_image {
    dbg_image_format format;
    bool             contains;
    uint64_t         base;
    uint64_t         header;
    uint64_t         size;
    uint64_t         lowest;
    char             name[128];
    char             debug_path[DBG_FIND_PATH];
    char             file[DBG_FIND_PATH];
    uint8_t          build_id[32];
    uint32_t         build_id_len;
} dbg_image;

dbg_status  dbg_find_image(dbg_ctx *dbg, uint64_t addr, dbg_image *out);

typedef struct dbg_local {
    bool        is_param;
    bool        expandable;
    const char *name;
    const char *type;
    const char *value;
} dbg_local;

typedef void (*dbg_local_fn)(void *user, const dbg_local *local);

dbg_status  dbg_locals(dbg_ctx *dbg, dbg_local_fn fn, void *user);

typedef struct dbg_frame {
    uint32_t number;
    uint64_t pc;
    uint64_t sp;
    uint64_t cfa;
    uint64_t return_addr;
    bool     have_cfa;
    bool     have_return;
} dbg_frame;

typedef bool (*dbg_frame_fn)(void *user, const dbg_frame *frame);

dbg_status  dbg_stack_walk(dbg_ctx *dbg, uint32_t max_frames, dbg_frame_fn fn, void *user);

dbg_status  dbg_set_frame(dbg_ctx *dbg, uint32_t number);
uint32_t    dbg_get_frame(const dbg_ctx *dbg);
dbg_status  dbg_frame_info(dbg_ctx *dbg, dbg_frame *out);
dbg_status  dbg_frame_params(dbg_ctx *dbg, const dbg_frame *frame, dbg_local_fn fn,
                             void *user);

typedef struct dbg_eval_result {
    char type[128];
    char value[256];
    bool expandable;
} dbg_eval_result;

typedef struct dbg_eval_child {
    const char            *name;
    const char            *expr;
    const dbg_eval_result *result;
} dbg_eval_child;

typedef void (*dbg_eval_child_fn)(void *user, const dbg_eval_child *child);

dbg_status  dbg_eval(dbg_ctx *dbg, const char *expr, dbg_eval_result *out);
dbg_status  dbg_eval_children(dbg_ctx *dbg, const char *expr, dbg_eval_child_fn fn,
                              void *user);

bool        dbg_source_at(dbg_ctx *dbg, uint64_t addr, dbg_source *out);
dbg_status  dbg_line_addr(dbg_ctx *dbg, const char *file, uint32_t line, uint64_t *addr);

#ifdef __cplusplus
}
#endif

#endif
