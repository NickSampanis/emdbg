#include "dbg.h"

#include <stdlib.h>
#include <string.h>

#define INT3 0xCC

#define DR7_SLOT_MASK(slot)  ((3ull << ((slot) * 2)) | (0xFull << (16 + (slot) * 4)))

static const char *const dr_names[] = { "dr0", "dr1", "dr2", "dr3" };

static int lower_bound(const dbg_ctx *dbg, uint64_t addr)
{
    int low;
    int high;
    int middle;

    low = 0;
    high = dbg->bp_count;
    while (low < high) {
        middle = low + (high - low) / 2;
        if (dbg->bps[middle].pub.addr < addr)
            low = middle + 1;
        else
            high = middle;
    }
    return low;
}

static int index_of(const dbg_ctx *dbg, uint32_t id)
{
    int index;

    for (index = 0; index < dbg->bp_count; index++)
        if (dbg->bps[index].pub.id == id)
            return index;
    return -1;
}

bp_entry *bp_by_id(dbg_ctx *dbg, uint32_t id)
{
    int index;

    index = index_of(dbg, id);
    return index < 0 ? NULL : &dbg->bps[index];
}

bp_entry *bp_exec_at(dbg_ctx *dbg, uint64_t addr)
{
    int index;

    for (index = lower_bound(dbg, addr);
         index < dbg->bp_count && dbg->bps[index].pub.addr == addr; index++)
        if (dbg->bps[index].pub.type == EM_BP_EXEC && dbg->bps[index].pub.planted)
            return &dbg->bps[index];
    if (dbg->temp_bp.pub.planted && dbg->temp_bp.pub.addr == addr)
        return &dbg->temp_bp;
    return NULL;
}

static bool stub_hit(const bp_entry *entry, uint8_t reason, uint64_t addr)
{
    if (!entry->pub.planted || entry->impl != BP_IMPL_STUB)
        return false;
    if (reason == EM_STOP_BREAKPOINT)
        return entry->pub.type == EM_BP_EXEC && entry->pub.addr == addr;
    return entry->pub.type != EM_BP_EXEC && addr >= entry->pub.addr &&
           addr - entry->pub.addr < entry->pub.len;
}

static bp_entry *stub_hit_at(dbg_ctx *dbg, uint8_t reason, uint64_t addr)
{
    int index;

    for (index = 0; index < dbg->bp_count; index++)
        if (stub_hit(&dbg->bps[index], reason, addr))
            return &dbg->bps[index];
    if (stub_hit(&dbg->temp_bp, reason, addr))
        return &dbg->temp_bp;
    return NULL;
}

static uint64_t *dr_addr(em_x86_regs *regs, int slot)
{
    switch (slot) {
        case 0:
            return &regs->ctrl.dr0;
        case 1:
            return &regs->ctrl.dr1;
        case 2:
            return &regs->ctrl.dr2;
        default:
            return &regs->ctrl.dr3;
    }
}

static uint64_t dr7_bits(int slot, uint8_t type, uint8_t len)
{
    uint64_t rw_bits;
    uint64_t len_bits;

    rw_bits = type == EM_BP_EXEC ? 0 : type == EM_BP_WRITE ? 1 : 3;
    len_bits = len == 1 ? 0 : len == 2 ? 1 : len == 8 ? 2 : 3;
    return (1ull << (slot * 2)) | ((rw_bits | (len_bits << 2)) << (16 + slot * 4));
}

static int dr_free_slot(const dbg_ctx *dbg)
{
    unsigned used;
    int      index;

    used = 0;
    for (index = 0; index < dbg->bp_count; index++)
        if (dbg->bps[index].pub.planted && dbg->bps[index].impl == BP_IMPL_DR)
            used |= 1u << dbg->bps[index].dr;
    for (index = 0; index < 4; index++)
        if (!(used & (1u << index)))
            return index;
    return -1;
}

static bool stub_can(const dbg_ctx *dbg, uint8_t type)
{
    if (dbg->force_soft_bp || !dbg_target_supports(dbg, EM_CMD_BP_SET))
        return false;
    return type == EM_BP_EXEC || (dbg->target.features & EM_FEAT_HW_WATCH);
}

dbg_status bp_plant(dbg_ctx *dbg, bp_entry *entry)
{
    em_bp_req  bp_req;
    bp_entry  *other;
    uint8_t    int3;
    uint32_t   read_len;
    int        slot;
    dbg_status status;

    int3 = INT3;
    if (entry->pub.planted)
        return DBG_OK;
    if (!dbg->link.open)
        return DBG_E_DISCONNECTED;

    if (stub_can(dbg, entry->pub.type)) {
        memset(&bp_req, 0, sizeof bp_req);
        bp_req.addr  = entry->pub.addr;
        bp_req.len   = entry->pub.len;
        bp_req.type  = entry->pub.type;
        bp_req.space = EM_SPACE_VIRT;
        bp_req.cpu   = EM_CPU_ALL;
        status = link_call(&dbg->link, EM_CMD_BP_SET, &bp_req, sizeof bp_req, NULL, 0, NULL, 0,
                           NULL, DBG_CALL_TIMEOUT_MS);
        if (status != DBG_OK)
            return status;
        entry->impl = BP_IMPL_STUB;
    } else if (entry->pub.type == EM_BP_EXEC) {
        other = bp_exec_at(dbg, entry->pub.addr);
        if (other && other->impl == BP_IMPL_SOFT)
            return DBG_E_BADARG;
        read_len = 0;
        status = mem_read_raw(dbg, EM_SPACE_VIRT, entry->pub.addr, &entry->orig, 1, &read_len);
        if (status == DBG_OK)
            status = mem_write_raw(dbg, EM_SPACE_VIRT, entry->pub.addr, &int3, 1);
        if (status != DBG_OK)
            return status;
        entry->impl = BP_IMPL_SOFT;
        dbg->soft_planted++;
    } else {
        if (dbg->state != DBG_STATE_STOPPED || !(dbg->regs.valid & EM_RB_BIT(EM_RB_X86_CTRL)))
            return DBG_E_RUNNING;
        slot = dr_free_slot(dbg);
        if (slot < 0)
            return DBG_E_UNSUPPORTED;
        *dr_addr(&dbg->regs, slot) = entry->pub.addr;
        dbg->regs.ctrl.dr7 = (dbg->regs.ctrl.dr7 & ~DR7_SLOT_MASK(slot)) |
                             dr7_bits(slot, entry->pub.type, entry->pub.len);
        status = regs_put_raw(dbg, EM_RB_X86_CTRL);
        if (status != DBG_OK)
            return status;
        entry->impl = BP_IMPL_DR;
        entry->dr = (uint8_t)slot;
    }
    entry->pub.planted = true;
    entry->warned = false;
    return DBG_OK;
}

dbg_status bp_unplant(dbg_ctx *dbg, bp_entry *entry)
{
    em_bp_req  bp_req;

    if (!entry->pub.planted)
        return DBG_OK;
    if (entry->impl == BP_IMPL_DR && dbg->link.open && dbg->state != DBG_STATE_STOPPED)
        return DBG_E_RUNNING;

    entry->pub.planted = false;
    if (entry->impl == BP_IMPL_SOFT)
        dbg->soft_planted--;
    if (!dbg->link.open)
        return DBG_E_DISCONNECTED;

    switch (entry->impl) {
        case BP_IMPL_STUB:
            memset(&bp_req, 0, sizeof bp_req);
            bp_req.addr  = entry->pub.addr;
            bp_req.len   = entry->pub.len;
            bp_req.type  = entry->pub.type;
            bp_req.space = EM_SPACE_VIRT;
            bp_req.cpu   = EM_CPU_ALL;
            return link_call(&dbg->link, EM_CMD_BP_CLEAR, &bp_req, sizeof bp_req, NULL, 0, NULL,
                             0, NULL, DBG_CALL_TIMEOUT_MS);
        case BP_IMPL_SOFT:
            return mem_write_raw(dbg, EM_SPACE_VIRT, entry->pub.addr, &entry->orig, 1);
        case BP_IMPL_DR:
            *dr_addr(&dbg->regs, entry->dr) = 0;
            dbg->regs.ctrl.dr7 &= ~DR7_SLOT_MASK(entry->dr);
            return regs_put_raw(dbg, EM_RB_X86_CTRL);
    }
    return DBG_OK;
}

void bp_plant_pending(dbg_ctx *dbg)
{
    bp_entry  *entry;
    dbg_status status;
    int        index;

    for (index = 0; index < dbg->bp_count && dbg->link.open; index++) {
        entry = &dbg->bps[index];
        if (!entry->pub.enabled || entry->pub.planted || entry->pub.id == dbg->lifted_id)
            continue;
        status = bp_plant(dbg, entry);
        if (status != DBG_OK && status != DBG_E_RUNNING && !entry->warned) {
            entry->warned = true;
            dbg_out(dbg, DBG_OUT_ERROR, "breakpoint %u at %llx could not be set: %s\n",
                    entry->pub.id, (unsigned long long)entry->pub.addr, dbg_status_str(status));
        }
    }
}

void bp_unplant_all(dbg_ctx *dbg)
{
    int index;

    for (index = 0; index < dbg->bp_count; index++)
        bp_unplant(dbg, &dbg->bps[index]);
    bp_unplant(dbg, &dbg->temp_bp);
}

void bp_forget_planted(dbg_ctx *dbg)
{
    int index;

    for (index = 0; index < dbg->bp_count; index++)
        dbg->bps[index].pub.planted = false;
    dbg->temp_bp.pub.planted = false;
    dbg->soft_planted = 0;
    dbg->lifted_id = 0;
    dbg->stop_landed = false;
    dbg->step_out_sp = 0;
    dbg->plan.kind = PLAN_NONE;
}

void bp_hide(const dbg_ctx *dbg, uint64_t addr, uint8_t *buf, uint32_t len)
{
    const bp_entry *entry;
    int             index;

    if (!dbg->soft_planted)
        return;
    for (index = lower_bound(dbg, addr);
         index < dbg->bp_count && dbg->bps[index].pub.addr < addr + len; index++) {
        entry = &dbg->bps[index];
        if (entry->pub.planted && entry->impl == BP_IMPL_SOFT)
            buf[entry->pub.addr - addr] = entry->orig;
    }
    entry = &dbg->temp_bp;
    if (entry->pub.planted && entry->impl == BP_IMPL_SOFT && entry->pub.addr >= addr &&
        entry->pub.addr < addr + len)
        buf[entry->pub.addr - addr] = entry->orig;
}

void bp_mask_write(dbg_ctx *dbg, uint64_t addr, uint8_t *buf, uint32_t len)
{
    bp_entry *entry;
    int       index;

    if (!dbg->soft_planted)
        return;
    for (index = lower_bound(dbg, addr);
         index < dbg->bp_count && dbg->bps[index].pub.addr < addr + len; index++) {
        entry = &dbg->bps[index];
        if (entry->pub.planted && entry->impl == BP_IMPL_SOFT) {
            entry->orig = buf[entry->pub.addr - addr];
            buf[entry->pub.addr - addr] = INT3;
        }
    }
    entry = &dbg->temp_bp;
    if (entry->pub.planted && entry->impl == BP_IMPL_SOFT && entry->pub.addr >= addr &&
        entry->pub.addr < addr + len) {
        entry->orig = buf[entry->pub.addr - addr];
        buf[entry->pub.addr - addr] = INT3;
    }
}

dbg_status bp_temp_plant(dbg_ctx *dbg, uint64_t addr)
{
    if (bp_exec_at(dbg, addr))
        return DBG_OK;
    memset(&dbg->temp_bp, 0, sizeof dbg->temp_bp);
    dbg->temp_bp.pub.addr = addr;
    dbg->temp_bp.pub.type = EM_BP_EXEC;
    dbg->temp_bp.pub.len = 1;
    dbg->temp_bp.pub.enabled = true;
    return bp_plant(dbg, &dbg->temp_bp);
}

dbg_status bp_lift_at(dbg_ctx *dbg, uint64_t pc)
{
    bp_entry  *entry;
    dbg_status status;

    entry = bp_exec_at(dbg, pc);
    if (!entry || entry == &dbg->temp_bp || entry->impl != BP_IMPL_SOFT)
        return DBG_OK;
    status = bp_unplant(dbg, entry);
    if (status == DBG_OK)
        dbg->lifted_id = entry->pub.id;
    return status;
}

bool bp_on_stop(dbg_ctx *dbg)
{
    em_stopped *stop;
    bp_entry   *hit;
    bp_entry   *entry;
    uint8_t     vector;
    uint64_t    slots;
    bool        landed;
    bool        temp_hit;
    int         index;

    stop = &dbg->last_stop;
    hit = NULL;
    vector = (uint8_t)stop->addr;
    landed = dbg->stop_landed;
    dbg->stop_landed = false;

    if (stop->reason == EM_STOP_BREAKPOINT) {
        hit = stub_hit_at(dbg, stop->reason, dbg_pc(dbg));
    } else if (stop->reason == EM_STOP_WATCH) {
        hit = stub_hit_at(dbg, stop->reason, stop->addr);
    } else if (stop->reason == EM_STOP_EXCEPTION && vector == 3 && dbg->soft_planted) {
        hit = bp_exec_at(dbg, dbg_pc(dbg) - 1);
        if (hit && hit->impl == BP_IMPL_SOFT) {
            dbg->regs.core.rip--;
            regs_put_raw(dbg, EM_RB_X86_CORE);
        } else {
            hit = NULL;
        }
    } else if (stop->reason == EM_STOP_EXCEPTION && vector == 1 &&
               (dbg->regs.valid & EM_RB_BIT(EM_RB_X86_CTRL))) {
        slots = dbg->regs.ctrl.dr6 & 0xF;
        for (index = 0; index < dbg->bp_count && !hit; index++) {
            entry = &dbg->bps[index];
            if (entry->pub.planted && entry->impl == BP_IMPL_DR && (slots & (1u << entry->dr)))
                hit = entry;
        }
        if (slots) {
            dbg->regs.ctrl.dr6 &= ~0xFull;
            regs_put_raw(dbg, EM_RB_X86_CTRL);
        }
    } else if (landed && stop->reason == EM_STOP_STEP) {
        hit = bp_exec_at(dbg, dbg_pc(dbg));
    }

    temp_hit = hit && hit == &dbg->temp_bp;
    dbg->temp_hit = temp_hit;
    if (temp_hit && dbg->step_out_sp && dbg_stack_pointer(dbg) < dbg->step_out_sp)
        return true;
    dbg->step_out_sp = 0;
    bp_unplant(dbg, &dbg->temp_bp);
    if (dbg->lifted_id) {
        entry = bp_by_id(dbg, dbg->lifted_id);
        dbg->lifted_id = 0;
        if (entry && entry->pub.enabled)
            bp_plant(dbg, entry);
    }

    if (temp_hit) {
        stop->reason = EM_STOP_STEP;
        stop->bp_id = 0;
    } else if (hit) {
        hit->pub.hits++;
        stop->bp_id = hit->pub.id;
        if (hit->pub.type == EM_BP_EXEC) {
            stop->reason = EM_STOP_BREAKPOINT;
            dbg_out(dbg, DBG_OUT_NORMAL, "Breakpoint %u hit\n", hit->pub.id);
        } else {
            stop->reason = EM_STOP_WATCH;
            stop->addr = hit->pub.addr;
            dbg_out(dbg, DBG_OUT_NORMAL, "Breakpoint %u hit (data at %llx)\n", hit->pub.id,
                    (unsigned long long)hit->pub.addr);
        }
    }
    bp_plant_pending(dbg);
    return false;
}

dbg_status bp_step_out_resume(dbg_ctx *dbg)
{
    dbg_status status;

    if (dbg->temp_bp.impl == BP_IMPL_SOFT) {
        status = bp_unplant(dbg, &dbg->temp_bp);
        if (status == DBG_OK)
            status = step_raw(dbg);
        dbg->stop_raw = false;
        if (status == DBG_OK && dbg->last_stop.reason != EM_STOP_STEP)
            status = DBG_E_BADARG;
        if (status == DBG_OK)
            status = bp_plant(dbg, &dbg->temp_bp);
        if (status != DBG_OK)
            return status;
    }
    return resume_raw(dbg);
}

void bp_step_out_abort(dbg_ctx *dbg)
{
    bp_entry *entry;

    dbg->step_out_sp = 0;
    bp_unplant(dbg, &dbg->temp_bp);
    if (dbg->lifted_id) {
        entry = bp_by_id(dbg, dbg->lifted_id);
        dbg->lifted_id = 0;
        if (entry && entry->pub.enabled)
            bp_plant(dbg, entry);
    }
}

dbg_status bp_step_off(dbg_ctx *dbg, bool *stepped)
{
    bp_entry  *entry;
    uint32_t   id;
    dbg_status status;
    dbg_status plant_status;

    *stepped = false;
    entry = bp_exec_at(dbg, dbg_pc(dbg));
    if (!entry || entry == &dbg->temp_bp || entry->impl != BP_IMPL_SOFT)
        return DBG_OK;

    id = entry->pub.id;
    status = bp_unplant(dbg, entry);
    if (status != DBG_OK)
        return status;
    status = step_raw(dbg);
    *stepped = true;
    entry = bp_by_id(dbg, id);
    if (entry && entry->pub.enabled) {
        plant_status = bp_plant(dbg, entry);
        if (status == DBG_OK)
            status = plant_status;
    }
    return status;
}

dbg_status dbg_bp_add(dbg_ctx *dbg, uint8_t type, uint64_t addr, uint8_t len, uint32_t *id)
{
    bp_entry  *grown;
    bp_entry  *entry;
    int        index;
    int        capacity;
    dbg_status status;

    status = DBG_OK;
    if (type > EM_BP_ACCESS)
        return DBG_E_BADARG;
    if (type == EM_BP_EXEC)
        len = 1;
    else if ((len != 1 && len != 2 && len != 4 && len != 8) || (addr & (uint64_t)(len - 1)))
        return DBG_E_BADARG;

    for (index = lower_bound(dbg, addr);
         index < dbg->bp_count && dbg->bps[index].pub.addr == addr; index++) {
        if (dbg->bps[index].pub.type == type) {
            if (id)
                *id = dbg->bps[index].pub.id;
            return DBG_OK;
        }
    }

    if (dbg->bp_count == dbg->bp_cap) {
        capacity = dbg->bp_cap ? dbg->bp_cap * 2 : 16;
        grown = realloc(dbg->bps, (size_t)capacity * sizeof *grown);
        if (!grown)
            return DBG_E_NOMEM;
        dbg->bps = grown;
        dbg->bp_cap = capacity;
    }
    index = lower_bound(dbg, addr);
    memmove(&dbg->bps[index + 1], &dbg->bps[index],
            (size_t)(dbg->bp_count - index) * sizeof *dbg->bps);
    entry = &dbg->bps[index];
    memset(entry, 0, sizeof *entry);
    entry->pub.id = ++dbg->next_bp_id;
    entry->pub.addr = addr;
    entry->pub.type = type;
    entry->pub.len = len;
    entry->pub.enabled = true;
    dbg->bp_count++;
    if (id)
        *id = entry->pub.id;

    if (dbg->link.open) {
        status = bp_plant(dbg, entry);
        if (status == DBG_E_RUNNING)
            status = DBG_OK;
        if (status != DBG_OK) {
            memmove(&dbg->bps[index], &dbg->bps[index + 1],
                    (size_t)(dbg->bp_count - index - 1) * sizeof *dbg->bps);
            dbg->bp_count--;
        }
    }
    return dbg_finish(dbg, status);
}

dbg_status dbg_bp_remove(dbg_ctx *dbg, uint32_t id)
{
    int        index;
    dbg_status status;

    index = index_of(dbg, id);
    if (index < 0)
        return DBG_E_BADARG;
    status = bp_unplant(dbg, &dbg->bps[index]);
    if (status == DBG_E_RUNNING)
        return DBG_E_RUNNING;
    if (dbg->lifted_id == id)
        dbg->lifted_id = 0;
    memmove(&dbg->bps[index], &dbg->bps[index + 1],
            (size_t)(dbg->bp_count - index - 1) * sizeof *dbg->bps);
    dbg->bp_count--;
    return dbg_finish(dbg, status == DBG_E_DISCONNECTED ? DBG_OK : status);
}

dbg_status dbg_bp_enable(dbg_ctx *dbg, uint32_t id, bool enable)
{
    bp_entry  *entry;
    dbg_status status;

    status = DBG_OK;
    entry = bp_by_id(dbg, id);
    if (!entry)
        return DBG_E_BADARG;
    entry->pub.enabled = enable;
    entry->warned = false;
    if (dbg->link.open) {
        status = enable ? bp_plant(dbg, entry) : bp_unplant(dbg, entry);
        if (enable && status == DBG_E_RUNNING)
            status = DBG_OK;
    }
    return dbg_finish(dbg, status);
}

int dbg_bp_count(const dbg_ctx *dbg)
{
    return dbg->bp_count;
}

const dbg_bp *dbg_bp_get(const dbg_ctx *dbg, int index)
{
    return index >= 0 && index < dbg->bp_count ? &dbg->bps[index].pub : NULL;
}

const dbg_bp *dbg_bp_find(const dbg_ctx *dbg, uint64_t addr)
{
    int index;

    for (index = lower_bound(dbg, addr);
         index < dbg->bp_count && dbg->bps[index].pub.addr == addr; index++)
        if (dbg->bps[index].pub.type == EM_BP_EXEC)
            return &dbg->bps[index].pub;
    return NULL;
}

const char *dbg_bp_where(const dbg_ctx *dbg, uint32_t id)
{
    int index;

    index = index_of(dbg, id);
    if (index < 0 || !dbg->bps[index].pub.planted)
        return "-";
    switch (dbg->bps[index].impl) {
        case BP_IMPL_STUB:
            return "stub";
        case BP_IMPL_SOFT:
            return "int3";
        case BP_IMPL_DR:
            return dr_names[dbg->bps[index].dr & 3];
    }
    return "?";
}
