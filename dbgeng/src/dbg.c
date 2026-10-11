#include "dbg.h"
#include "disasm.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONNECT_TIMEOUT_MS  3000u

void dbg_out(dbg_ctx *dbg, dbg_out_kind kind, const char *fmt, ...)
{
    char    text[1024];
    va_list arg_list;

    if (!dbg->cb.output)
        return;
    va_start(arg_list, fmt);
    vsnprintf(text, sizeof text, fmt, arg_list);
    va_end(arg_list);
    dbg->cb.output(dbg->cb.user, kind, text);
}

static void emit(dbg_ctx *dbg, dbg_event_kind kind)
{
    dbg_event event;

    if (!dbg->cb.event)
        return;
    memset(&event, 0, sizeof event);
    event.kind = kind;
    if (kind == DBG_EV_STOPPED) {
        event.cpu    = dbg->last_stop.cpu;
        event.reason = (em_stop_reason)dbg->last_stop.reason;
        event.bp_id  = dbg->last_stop.bp_id;
        event.addr   = dbg->last_stop.addr;
        event.pc     = dbg->regs.core.rip;
    }
    dbg->cb.event(dbg->cb.user, &event);
}

const char *dbg_status_str(dbg_status status)
{
    switch (status) {
        case DBG_OK:
            return "ok";
        case DBG_E_NOMEM:
            return "out of memory";
        case DBG_E_CONNECT:
            return "cannot connect";
        case DBG_E_DISCONNECTED:
            return "not connected";
        case DBG_E_PROTOCOL:
            return "protocol error";
        case DBG_E_TIMEOUT:
            return "target did not answer";
        case DBG_E_RUNNING:
            return "target is running";
        case DBG_E_UNSUPPORTED:
            return "not supported by the target";
        case DBG_E_BADARG:
            return "bad argument";
        case DBG_E_FAULT:
            return "memory not accessible";
        case DBG_E_PARTIAL:
            return "memory only partly accessible";
    }
    return "?";
}

static void *block_ptr(em_x86_regs *regs, uint32_t id)
{
    switch (id) {
        case EM_RB_X86_CORE:
            return &regs->core;
        case EM_RB_X86_SEG:
            return &regs->seg;
        case EM_RB_X86_CTRL:
            return &regs->ctrl;
        case EM_RB_X86_SYS:
            return &regs->sys;
        case EM_RB_X86_FPU:
            return &regs->fpu;
        case EM_RB_X86_VMX:
            return &regs->vmx;
    }
    return NULL;
}

static dbg_status parse_blocks(em_x86_regs *regs, const uint8_t *payload, uint32_t len)
{
    em_rb_hdr block_hdr;
    uint32_t  pos;
    uint32_t  local_size;
    void     *dst;

    pos = 0;
    while (pos + sizeof block_hdr <= len) {
        memcpy(&block_hdr, payload + pos, sizeof block_hdr);
        pos += (uint32_t)sizeof block_hdr;
        if (block_hdr.size > len - pos)
            return DBG_E_PROTOCOL;
        dst        = block_ptr(regs, block_hdr.id);
        local_size = em_x86_rb_size(block_hdr.id);
        if (dst) {
            memset(dst, 0, local_size);
            memcpy(dst, payload + pos, block_hdr.size < local_size ? block_hdr.size : local_size);
            regs->valid |= EM_RB_BIT(block_hdr.id);
        }
        pos += block_hdr.size;
    }
    return pos == len ? DBG_OK : DBG_E_PROTOCOL;
}

static dbg_cpu_mode cpu_mode_of(const em_x86_regs *regs, dbg_cpu_mode fallback)
{
    if (!(regs->valid & EM_RB_BIT(EM_RB_X86_CTRL)) || !(regs->valid & EM_RB_BIT(EM_RB_X86_SEG)))
        return fallback;
    if (!(regs->ctrl.cr0 & 1))
        return DBG_MODE_REAL16;
    if ((regs->ctrl.efer & (1u << 10)) && EM_SEG_L(regs->seg.cs.attr))
        return DBG_MODE_LONG64;
    return EM_SEG_DB(regs->seg.cs.attr) ? DBG_MODE_PROT32 : DBG_MODE_PROT16;
}

static void process_stop(dbg_ctx *dbg);

static void on_stopped(dbg_ctx *dbg, const uint8_t *payload, uint32_t len)
{
    em_stopped stopped;

    if (len < sizeof stopped)
        return;
    memcpy(&stopped, payload, sizeof stopped);
    dbg->regs.valid = 0;
    if (parse_blocks(&dbg->regs, payload + sizeof stopped, len - (uint32_t)sizeof stopped) != DBG_OK)
        dbg_out(dbg, DBG_OUT_ERROR, "malformed register blocks in stop event\n");
    dbg->last_stop = stopped;
    dbg->cpu = stopped.cpu;
    dbg->mode = cpu_mode_of(&dbg->regs, dbg->mode);
    dbg->state = DBG_STATE_STOPPED;
    dbg->stop_raw = true;
}

static void on_output(dbg_ctx *dbg, const uint8_t *payload, uint32_t len)
{
    char     text[1024];
    uint32_t chunk;

    while (len) {
        chunk = len < sizeof text - 1 ? len : (uint32_t)sizeof text - 1;
        memcpy(text, payload, chunk);
        text[chunk] = '\0';
        if (dbg->cb.output)
            dbg->cb.output(dbg->cb.user, DBG_OUT_TARGET, text);
        payload += chunk;
        len -= chunk;
    }
}

static void on_event(void *user, uint16_t type, const uint8_t *payload, uint32_t len)
{
    dbg_ctx *dbg;

    dbg = (dbg_ctx *)user;
    switch (type) {
        case EM_EV_STOPPED:
            on_stopped(dbg, payload, len);
            break;
        case EM_EV_OUTPUT:
            on_output(dbg, payload, len);
            break;
        default:
            break;
    }
}

static dbg_status check_link(dbg_ctx *dbg, dbg_status status)
{
    if (!dbg->link.open) {
        if (dbg->state != DBG_STATE_DISCONNECTED) {
            dbg->state = DBG_STATE_DISCONNECTED;
            dbg->have_target = false;
            dbg->regs.valid = 0;
            dbg->stop_raw = false;
            bp_forget_planted(dbg);
            unwind_forget(dbg);
            dbg_out(dbg, DBG_OUT_ERROR, "connection to the target was lost\n");
            emit(dbg, DBG_EV_DISCONNECTED);
        }
        return status;
    }
    process_stop(dbg);
    return status;
}

dbg_status dbg_finish(dbg_ctx *dbg, dbg_status status)
{
    return check_link(dbg, status);
}

static dbg_status require_stopped(const dbg_ctx *dbg)
{
    if (dbg->state == DBG_STATE_DISCONNECTED)
        return DBG_E_DISCONNECTED;
    if (dbg->state != DBG_STATE_STOPPED)
        return DBG_E_RUNNING;
    return DBG_OK;
}

static void wait_stopped(dbg_ctx *dbg, uint32_t timeout_ms)
{
    uint64_t deadline;
    uint64_t now;

    deadline = plat_time_ms() + timeout_ms;
    while (dbg->link.open && dbg->state != DBG_STATE_STOPPED) {
        now = plat_time_ms();
        if (now >= deadline)
            break;
        link_pump(&dbg->link, (uint32_t)(deadline - now));
    }
}

dbg_ctx *dbg_create(const dbg_callbacks *callbacks)
{
    dbg_ctx *dbg;

    if (plat_net_init() != 0)
        return NULL;
    dbg = calloc(1, sizeof *dbg);
    if (!dbg) {
        plat_net_cleanup();
        return NULL;
    }
    dbg->scratch = malloc(LINK_MAX_PAYLOAD + 1);
    if (!dbg->scratch) {
        free(dbg);
        plat_net_cleanup();
        return NULL;
    }
    if (callbacks)
        dbg->cb = *callbacks;
    dbg->state = DBG_STATE_DISCONNECTED;
    dbg->link.sock = PLAT_SOCK_INVALID;
    return dbg;
}

void dbg_destroy(dbg_ctx *dbg)
{
    if (!dbg)
        return;
    link_close(&dbg->link);
    free(dbg->bps);
    free(dbg->scratch);
    sym_free_all(dbg);
    unwind_forget(dbg);
    free(dbg);
    plat_net_cleanup();
}

dbg_status dbg_connect(dbg_ctx *dbg, const char *host, uint16_t port)
{
    em_hello_req hello_req;
    uint32_t     reply_len;
    dbg_status   status;

    dbg_disconnect(dbg);
    status = link_open(&dbg->link, host, port, CONNECT_TIMEOUT_MS, on_event, dbg);
    if (status != DBG_OK) {
        dbg_out(dbg, DBG_OUT_ERROR, "cannot connect to %s:%u\n", host, (unsigned)port);
        return status;
    }

    dbg->state = DBG_STATE_RUNNING;
    dbg->stop_raw = false;
    dbg->mode = DBG_MODE_LONG64;

    hello_req.version = EM_PROTO_VERSION;
    hello_req.max_payload = LINK_MAX_PAYLOAD;
    status = link_call(&dbg->link, EM_CMD_HELLO, &hello_req, sizeof hello_req, NULL, 0,
                       &dbg->target, sizeof dbg->target, &reply_len, DBG_CALL_TIMEOUT_MS);
    if (status == DBG_OK && reply_len < sizeof dbg->target)
        status = DBG_E_PROTOCOL;
    if (status != DBG_OK) {
        dbg_out(dbg, DBG_OUT_ERROR, "handshake with %s:%u failed: %s\n", host, (unsigned)port,
                dbg_status_str(status));
        link_close(&dbg->link);
        dbg->state = DBG_STATE_DISCONNECTED;
        return status;
    }

    dbg->target.target[sizeof dbg->target.target - 1] = '\0';
    dbg->link.peer_max = dbg->target.max_payload < EM_MIN_PAYLOAD ? EM_MIN_PAYLOAD
                       : dbg->target.max_payload > LINK_MAX_PAYLOAD ? LINK_MAX_PAYLOAD
                       : dbg->target.max_payload;
    dbg->have_target = true;

    if (dbg->target.version != EM_PROTO_VERSION)
        dbg_out(dbg, DBG_OUT_ERROR, "warning: target speaks protocol v%u, dbgeng v%u\n",
                dbg->target.version, EM_PROTO_VERSION);
    dbg_out(dbg, DBG_OUT_NORMAL, "connected to '%s' at %s:%u, %u cpu(s)\n", dbg->target.target,
            host, (unsigned)port, dbg->target.cpu_count);
    emit(dbg, DBG_EV_CONNECTED);
    bp_plant_pending(dbg);
    return check_link(dbg, DBG_OK);
}

void dbg_disconnect(dbg_ctx *dbg)
{
    bool was_connected;

    was_connected = dbg->state != DBG_STATE_DISCONNECTED;
    if (dbg->link.open)
        bp_unplant_all(dbg);
    link_close(&dbg->link);
    dbg->state = DBG_STATE_DISCONNECTED;
    dbg->have_target = false;
    dbg->regs.valid = 0;
    dbg->stop_raw = false;
    bp_forget_planted(dbg);
    unwind_forget(dbg);
    if (was_connected)
        emit(dbg, DBG_EV_DISCONNECTED);
}

void dbg_poll(dbg_ctx *dbg)
{
    if (!dbg->link.open) {
        check_link(dbg, DBG_OK);
        return;
    }
    link_pump(&dbg->link, 0);
    check_link(dbg, DBG_OK);
}

dbg_state dbg_get_state(const dbg_ctx *dbg)
{
    return dbg->state;
}

const em_hello_rep *dbg_target(const dbg_ctx *dbg)
{
    return dbg->have_target ? &dbg->target : NULL;
}

bool dbg_target_supports(const dbg_ctx *dbg, em_cmd cmd)
{
    uint32_t id;

    id = (uint32_t)cmd;
    return dbg->have_target && id < EM_CMD_ID_LIMIT &&
           (dbg->target.commands[id / 64] & (1ull << (id % 64))) != 0;
}

uint16_t dbg_current_cpu(const dbg_ctx *dbg)
{
    return dbg->cpu;
}

const em_x86_regs *dbg_regs(const dbg_ctx *dbg)
{
    if (dbg->state != DBG_STATE_STOPPED || !(dbg->regs.valid & EM_RB_BIT(EM_RB_X86_CORE)))
        return NULL;
    return &dbg->regs;
}

dbg_status dbg_fetch_regs(dbg_ctx *dbg, uint32_t blocks)
{
    em_regs_req regs_req;
    uint32_t    reply_len;
    dbg_status  status;

    status = require_stopped(dbg);
    if (status != DBG_OK)
        return status;
    regs_req.cpu = dbg->cpu;
    regs_req.reserved = 0;
    regs_req.blocks = blocks;
    status = link_call(&dbg->link, EM_CMD_GET_REGS, &regs_req, sizeof regs_req, NULL, 0,
                       dbg->scratch, LINK_MAX_PAYLOAD, &reply_len, DBG_CALL_TIMEOUT_MS);
    if (status == DBG_OK)
        status = parse_blocks(&dbg->regs, dbg->scratch, reply_len);
    return check_link(dbg, status);
}

dbg_status regs_put_raw(dbg_ctx *dbg, uint32_t block)
{
    struct {
        em_regs_req req;
        em_rb_hdr   block_hdr;
    } set_req;
    const void *data;
    uint32_t    size;
    dbg_status  status;

    size = em_x86_rb_size(block);
    status = require_stopped(dbg);
    if (status != DBG_OK)
        return status;
    data = block_ptr(&dbg->regs, block);
    if (!data || !(dbg->regs.valid & EM_RB_BIT(block)))
        return DBG_E_BADARG;

    memset(&set_req, 0, sizeof set_req);
    set_req.req.cpu = dbg->cpu;
    set_req.block_hdr.id = (uint16_t)block;
    set_req.block_hdr.size = size;
    return link_call(&dbg->link, EM_CMD_SET_REGS, &set_req, sizeof set_req, data, size, NULL, 0,
                     NULL, DBG_CALL_TIMEOUT_MS);
}

dbg_status dbg_put_regs(dbg_ctx *dbg, uint32_t block)
{
    return check_link(dbg, regs_put_raw(dbg, block));
}

dbg_status mem_read_raw(dbg_ctx *dbg, uint8_t space, uint64_t addr, void *buf, uint32_t len,
                        uint32_t *done)
{
    em_mem_req mem_req;
    uint32_t   total;
    uint32_t   reply_len;
    dbg_status status;

    total = 0;
    status = DBG_OK;
    if (done)
        *done = 0;
    if (dbg->state == DBG_STATE_DISCONNECTED)
        return DBG_E_DISCONNECTED;

    while (total < len) {
        mem_req.addr     = addr + total;
        mem_req.len      = len - total < dbg->link.peer_max ? len - total : dbg->link.peer_max;
        mem_req.cpu      = dbg->cpu;
        mem_req.space    = space;
        mem_req.reserved = 0;
        status = link_call(&dbg->link, EM_CMD_READ_MEM, &mem_req, sizeof mem_req, NULL, 0,
                           (uint8_t *)buf + total, mem_req.len, &reply_len, DBG_CALL_TIMEOUT_MS);
        total += reply_len;
        if (status != DBG_OK)
            break;
    }
    if (done)
        *done = total;
    if (status == DBG_E_FAULT && total)
        status = DBG_E_PARTIAL;
    return status;
}

dbg_status mem_write_raw(dbg_ctx *dbg, uint8_t space, uint64_t addr, const void *buf,
                         uint32_t len)
{
    em_mem_req mem_req;
    uint32_t   total;
    uint32_t   chunk;
    dbg_status status;

    total = 0;
    chunk = dbg->link.peer_max - (uint32_t)sizeof mem_req;
    status = DBG_OK;
    if (dbg->state == DBG_STATE_DISCONNECTED)
        return DBG_E_DISCONNECTED;

    while (total < len) {
        mem_req.addr     = addr + total;
        mem_req.len      = len - total < chunk ? len - total : chunk;
        mem_req.cpu      = dbg->cpu;
        mem_req.space    = space;
        mem_req.reserved = 0;
        status = link_call(&dbg->link, EM_CMD_WRITE_MEM, &mem_req, sizeof mem_req,
                           (const uint8_t *)buf + total, mem_req.len, NULL, 0, NULL,
                           DBG_CALL_TIMEOUT_MS);
        if (status != DBG_OK)
            break;
        total += mem_req.len;
    }
    return status;
}

dbg_status dbg_read_mem(dbg_ctx *dbg, uint8_t space, uint64_t addr, void *buf, uint32_t len,
                        uint32_t *done)
{
    uint32_t   read_len;
    dbg_status status;

    read_len = 0;
    status = mem_read_raw(dbg, space, addr, buf, len, &read_len);
    if (space == EM_SPACE_VIRT)
        bp_hide(dbg, addr, (uint8_t *)buf, read_len);
    if (done)
        *done = read_len;
    return check_link(dbg, status);
}

dbg_status dbg_write_mem(dbg_ctx *dbg, uint8_t space, uint64_t addr, const void *buf,
                         uint32_t len, uint32_t *done)
{
    uint8_t   *copy;
    dbg_status status;

    copy = NULL;
    if (done)
        *done = 0;
    if (space == EM_SPACE_VIRT && dbg->soft_planted && len) {
        copy = malloc(len);
        if (!copy)
            return DBG_E_NOMEM;
        memcpy(copy, buf, len);
        bp_mask_write(dbg, addr, copy, len);
        buf = copy;
    }
    status = mem_write_raw(dbg, space, addr, buf, len);
    free(copy);
    if (done && status == DBG_OK)
        *done = len;
    return check_link(dbg, status);
}

dbg_status resume_raw(dbg_ctx *dbg)
{
    em_empty   empty_req;
    dbg_status status;

    memset(&empty_req, 0, sizeof empty_req);
    status = link_call(&dbg->link, EM_CMD_CONTINUE, &empty_req, sizeof empty_req, NULL, 0, NULL,
                       0, NULL, DBG_CALL_TIMEOUT_MS);
    if (status == DBG_OK) {
        dbg->state = DBG_STATE_RUNNING;
        dbg->regs.valid = 0;
    }
    return status;
}

dbg_status step_raw(dbg_ctx *dbg)
{
    em_step_req step_req;
    dbg_status  status;

    memset(&step_req, 0, sizeof step_req);
    step_req.cpu = dbg->cpu;
    status = link_call(&dbg->link, EM_CMD_STEP, &step_req, sizeof step_req, NULL, 0, NULL, 0,
                       NULL, DBG_CALL_TIMEOUT_MS);
    if (status != DBG_OK)
        return status;
    dbg->state = DBG_STATE_RUNNING;
    dbg->regs.valid = 0;
    wait_stopped(dbg, DBG_WAIT_STOP_MS);
    return dbg->state == DBG_STATE_STOPPED ? DBG_OK : DBG_E_TIMEOUT;
}

dbg_status dbg_continue(dbg_ctx *dbg)
{
    bool       stepped;
    bp_entry  *at_pc;
    dbg_status status;

    status = require_stopped(dbg);
    if (status != DBG_OK)
        return status;

    status = bp_step_off(dbg, &stepped);
    if (status != DBG_OK)
        return check_link(dbg, status);
    if (stepped) {
        at_pc = bp_exec_at(dbg, dbg_pc(dbg));
        if (dbg->last_stop.reason != EM_STOP_STEP || (at_pc && at_pc != &dbg->temp_bp)) {
            dbg->stop_landed = true;
            return check_link(dbg, DBG_OK);
        }
        dbg->stop_raw = false;
    }

    status = resume_raw(dbg);
    if (status == DBG_OK)
        emit(dbg, DBG_EV_RUNNING);
    return check_link(dbg, status);
}

dbg_status dbg_step(dbg_ctx *dbg)
{
    bool       stepped;
    dbg_status status;

    status = require_stopped(dbg);
    if (status != DBG_OK)
        return status;
    status = bp_step_off(dbg, &stepped);
    if (!stepped && status == DBG_OK)
        status = step_raw(dbg);
    if (status == DBG_E_TIMEOUT)
        status = DBG_OK;
    return check_link(dbg, status);
}

dbg_status dbg_pause(dbg_ctx *dbg)
{
    em_empty   empty_req;
    dbg_status status;

    if (dbg->state == DBG_STATE_DISCONNECTED)
        return DBG_E_DISCONNECTED;
    if (dbg->state == DBG_STATE_STOPPED)
        return DBG_OK;
    memset(&empty_req, 0, sizeof empty_req);
    status = link_call(&dbg->link, EM_CMD_PAUSE, &empty_req, sizeof empty_req, NULL, 0, NULL, 0,
                       NULL, DBG_CALL_TIMEOUT_MS);
    if (status == DBG_OK)
        wait_stopped(dbg, DBG_WAIT_STOP_MS);
    return check_link(dbg, status);
}

dbg_status dbg_translate(dbg_ctx *dbg, uint64_t va, uint64_t *pa, uint32_t *flags)
{
    em_xlate_req xlate_req;
    em_xlate_rep xlate_rep;
    uint32_t     reply_len;
    dbg_status   status;

    if (dbg->state == DBG_STATE_DISCONNECTED)
        return DBG_E_DISCONNECTED;
    if (!dbg_target_supports(dbg, EM_CMD_TRANSLATE))
        return DBG_E_UNSUPPORTED;
    memset(&xlate_req, 0, sizeof xlate_req);
    xlate_req.vaddr = va;
    xlate_req.cpu = dbg->cpu;
    status = link_call(&dbg->link, EM_CMD_TRANSLATE, &xlate_req, sizeof xlate_req, NULL, 0,
                       &xlate_rep, sizeof xlate_rep, &reply_len, DBG_CALL_TIMEOUT_MS);
    if (status == DBG_OK && reply_len < sizeof xlate_rep)
        status = DBG_E_PROTOCOL;
    if (status == DBG_OK) {
        *pa = xlate_rep.paddr;
        if (flags)
            *flags = xlate_rep.flags;
    }
    return check_link(dbg, status);
}

dbg_status dbg_monitor(dbg_ctx *dbg, const char *cmd)
{
    em_empty   empty_req;
    uint32_t   reply_len;
    dbg_status status;

    if (dbg->state == DBG_STATE_DISCONNECTED)
        return DBG_E_DISCONNECTED;
    if (!dbg_target_supports(dbg, EM_CMD_MONITOR))
        return DBG_E_UNSUPPORTED;
    memset(&empty_req, 0, sizeof empty_req);
    status = link_call(&dbg->link, EM_CMD_MONITOR, &empty_req, sizeof empty_req, cmd,
                       (uint32_t)strlen(cmd), dbg->scratch, LINK_MAX_PAYLOAD, &reply_len,
                       DBG_CALL_TIMEOUT_MS);
    if (status == DBG_OK && reply_len) {
        dbg->scratch[reply_len] = '\0';
        if (dbg->cb.output)
            dbg->cb.output(dbg->cb.user, DBG_OUT_TARGET, (const char *)dbg->scratch);
    }
    return check_link(dbg, status);
}

dbg_cpu_mode dbg_get_cpu_mode(const dbg_ctx *dbg)
{
    return dbg->mode;
}

uint64_t dbg_pc(const dbg_ctx *dbg)
{
    const em_x86_regs *regs;

    regs = dbg_regs(dbg);
    if (!regs)
        return 0;
    switch (dbg->mode) {
        case DBG_MODE_LONG64:
            return regs->core.rip;
        case DBG_MODE_PROT32:
            return (regs->seg.cs.base + (uint32_t)regs->core.rip) & 0xFFFFFFFFull;
        case DBG_MODE_PROT16:
        case DBG_MODE_REAL16:
            break;
    }
    return (regs->seg.cs.base + (uint16_t)regs->core.rip) & 0xFFFFFFFFull;
}

static void process_stop(dbg_ctx *dbg)
{
    plan_result result;

    while (dbg->stop_raw) {
        dbg->stop_raw = false;
        dbg->frame_index = 0;
        dbg->stop_generation++;
        if (bp_on_stop(dbg)) {
            if (bp_step_out_resume(dbg) == DBG_OK)
                return;
            bp_step_out_abort(dbg);
        }
        if (dbg->plan.kind != PLAN_NONE) {
            result = step_plan_on_stop(dbg);
            if (result == PLAN_RESUMED)
                return;
            if (result == PLAN_INTERRUPTED)
                continue;
        }
        if (dbg->link.open && dbg->state == DBG_STATE_STOPPED)
            emit(dbg, DBG_EV_STOPPED);
    }
}

void dbg_emit(dbg_ctx *dbg, dbg_event_kind kind)
{
    emit(dbg, kind);
}

uint64_t dbg_stack_pointer(const dbg_ctx *dbg)
{
    if (dbg->mode == DBG_MODE_LONG64)
        return dbg->regs.core.rsp;
    return (uint32_t)dbg->regs.core.rsp;
}

void dbg_settle(dbg_ctx *dbg, uint32_t timeout_ms)
{
    uint64_t deadline;
    uint64_t now;

    deadline = plat_time_ms() + timeout_ms;
    while (dbg->link.open) {
        if (dbg->stop_raw) {
            process_stop(dbg);
            continue;
        }
        if (dbg->state == DBG_STATE_STOPPED)
            break;
        now = plat_time_ms();
        if (now >= deadline)
            break;
        link_pump(&dbg->link, (uint32_t)(deadline - now));
    }
}

static dbg_status run_to(dbg_ctx *dbg, uint64_t pc, uint64_t target, uint64_t step_out_sp)
{
    dbg_status status;

    status = bp_lift_at(dbg, pc);
    if (status != DBG_OK)
        return check_link(dbg, status);
    dbg->step_out_sp = 0;
    if (!bp_exec_at(dbg, target)) {
        status = bp_temp_plant(dbg, target);
        dbg->step_out_sp = step_out_sp;
    }
    if (status == DBG_OK)
        status = resume_raw(dbg);
    if (status != DBG_OK) {
        bp_step_out_abort(dbg);
        return check_link(dbg, status);
    }
    wait_stopped(dbg, DBG_WAIT_STOP_MS);
    if (dbg->state == DBG_STATE_RUNNING)
        emit(dbg, DBG_EV_RUNNING);
    return check_link(dbg, DBG_OK);
}

dbg_status dbg_step_over(dbg_ctx *dbg)
{
    dbg_insn   insn;
    uint8_t    code[15];
    uint32_t   read_len;
    uint64_t   pc;
    uint64_t   next;
    bool       over;
    dbg_status status;

    read_len = 0;
    over = false;
    status = require_stopped(dbg);
    if (status != DBG_OK)
        return status;
    pc = dbg_pc(dbg);
    mem_read_raw(dbg, EM_SPACE_VIRT, pc, code, sizeof code, &read_len);
    bp_hide(dbg, pc, code, read_len);
    if (read_len)
        disasm_decode(dbg->mode, pc, code, read_len, &insn, &over);
    if (!over)
        return dbg_step(dbg);
    next = pc + insn.len;
    return run_to(dbg, pc, next, 0);
}

dbg_status dbg_step_out(dbg_ctx *dbg)
{
    uint64_t   cfa;
    uint64_t   return_addr;
    uint32_t   pointer_size;
    uint32_t   read_len;
    dbg_status status;

    cfa = 0;
    return_addr = 0;
    read_len = 0;
    status = require_stopped(dbg);
    if (status != DBG_OK)
        return status;
    if (!sym_frame_cfa(dbg, &cfa)) {
        dbg_out(dbg, DBG_OUT_ERROR,
                "step out: no frame information at %llx (load its symbols with lds)\n",
                (unsigned long long)dbg_pc(dbg));
        return DBG_E_UNSUPPORTED;
    }
    pointer_size = dbg->mode == DBG_MODE_LONG64 ? 8u : 4u;
    status = mem_read_raw(dbg, EM_SPACE_VIRT, cfa - pointer_size, &return_addr, pointer_size,
                          &read_len);
    if (read_len != pointer_size) {
        dbg_out(dbg, DBG_OUT_ERROR, "step out: cannot read the return address at %llx\n",
                (unsigned long long)(cfa - pointer_size));
        return check_link(dbg, status == DBG_OK ? DBG_E_FAULT : status);
    }
    return run_to(dbg, dbg_pc(dbg), return_addr, cfa);
}
