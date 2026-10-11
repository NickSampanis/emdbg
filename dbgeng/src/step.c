#include "dbg.h"
#include "disasm.h"

#include <string.h>

#define PLAN_SCAN_INSNS  64u
#define PLAN_MAX_STEPS   100000u

static bool decode_at(dbg_ctx *dbg, uint64_t addr, dbg_insn *insn)
{
    uint8_t  code[15];
    uint32_t read_len;

    read_len = 0;
    mem_read_raw(dbg, EM_SPACE_VIRT, addr, code, sizeof code, &read_len);
    bp_hide(dbg, addr, code, read_len);
    if (!read_len)
        return false;
    return disasm_decode(dbg->mode, addr, code, read_len, insn, NULL);
}

static uint64_t scan_ahead(dbg_ctx *dbg, uint64_t pc)
{
    dbg_insn insn;
    uint64_t addr;
    uint32_t count;

    addr = pc;
    for (count = 0; count < PLAN_SCAN_INSNS; count++) {
        if (dbg->plan.kind == PLAN_LINE && addr >= dbg->plan.line.end)
            return addr;
        if (!decode_at(dbg, addr, &insn) || insn.flow != DBG_FLOW_NONE)
            return addr;
        addr += insn.len;
    }
    return addr;
}

static bool same_line(const sym_line_info *left, const sym_line_info *right)
{
    return left->module == right->module && left->file == right->file &&
           left->line == right->line;
}

static bool line_continues(dbg_ctx *dbg, uint64_t pc)
{
    step_plan    *plan;
    sym_line_info now;
    dbg_insn      insn;

    plan = &dbg->plan;
    if (pc >= plan->line.start && pc < plan->line.end)
        return true;
    if (sym_line_at(dbg, pc, &now)) {
        plan->in_gap = false;
        if (!same_line(&now, &plan->line))
            return false;
        plan->line.start = now.start;
        plan->line.end = now.end;
        return true;
    }
    if (!plan->func_start || sym_func_start(dbg, pc) != plan->func_start ||
        !decode_at(dbg, pc, &insn))
        return false;
    plan->in_gap = true;
    plan->line.start = pc;
    plan->line.end = pc + insn.len;
    return true;
}

static plan_result plan_step(dbg_ctx *dbg)
{
    bool       stepped;
    dbg_status status;

    stepped = false;
    dbg->plan.steps++;
    status = bp_step_off(dbg, &stepped);
    if (status == DBG_OK && !stepped)
        status = step_raw(dbg);
    if (status != DBG_OK) {
        dbg->plan.status = status;
        return PLAN_FAILED;
    }
    if (dbg->last_stop.reason != EM_STOP_STEP)
        return PLAN_INTERRUPTED;
    dbg->stop_raw = false;
    return PLAN_LOOP;
}

static plan_result plan_resume(dbg_ctx *dbg, uint64_t target, uint8_t wait, uint64_t return_sp)
{
    dbg_status status;

    status = bp_lift_at(dbg, dbg_pc(dbg));
    if (status == DBG_OK)
        status = bp_temp_plant(dbg, target);
    if (status == DBG_OK)
        status = resume_raw(dbg);
    if (status != DBG_OK) {
        bp_step_out_abort(dbg);
        dbg->plan.status = status;
        return PLAN_FAILED;
    }
    dbg->plan.wait = wait;
    dbg->plan.target = target;
    dbg->plan.return_sp = return_sp;
    return PLAN_RESUMED;
}

static bool steps_into(const step_plan *plan)
{
    return plan->kind == PLAN_LINE && plan->into && !plan->in_gap;
}

static plan_result plan_advance(dbg_ctx *dbg)
{
    step_plan  *plan;
    dbg_insn    insn;
    uint64_t    pc;
    uint64_t    target;
    plan_result result;
    bool        known;
    bool        at_start;

    plan = &dbg->plan;
    for (;;) {
        if (plan->steps > PLAN_MAX_STEPS) {
            dbg_out(dbg, DBG_OUT_ERROR, "step: stopped after %u single steps\n", plan->steps);
            return PLAN_FINISHED;
        }
        at_start = plan->skip_first;
        plan->skip_first = false;
        pc = dbg_pc(dbg);
        if (plan->kind == PLAN_LINE && !line_continues(dbg, pc))
            return PLAN_FINISHED;
        known = decode_at(dbg, pc, &insn);
        if (known && insn.flow == DBG_FLOW_NONE) {
            target = scan_ahead(dbg, pc);
            if (target != pc)
                return plan_resume(dbg, target, WAIT_TARGET, 0);
        }
        if (known && !at_start) {
            if (plan->kind == PLAN_TO_BRANCH && insn.flow != DBG_FLOW_NONE)
                return PLAN_FINISHED;
            if (plan->kind == PLAN_TO_CALL && insn.flow == DBG_FLOW_CALL)
                return PLAN_FINISHED;
        }
        if (known && insn.flow == DBG_FLOW_CALL && !steps_into(plan))
            return plan_resume(dbg, pc + insn.len, WAIT_RETURN, dbg_stack_pointer(dbg));
        result = plan_step(dbg);
        if (result != PLAN_LOOP)
            return result;
        if (known && insn.flow == DBG_FLOW_CALL)
            return PLAN_FINISHED;
    }
}

static plan_result plan_finish(dbg_ctx *dbg, plan_result result)
{
    if (result != PLAN_RESUMED) {
        dbg->plan.kind = PLAN_NONE;
        dbg->plan.wait = WAIT_NONE;
    }
    return result;
}

void step_plan_cancel(dbg_ctx *dbg)
{
    dbg->plan.kind = PLAN_NONE;
    dbg->plan.wait = WAIT_NONE;
}

plan_result step_plan_on_stop(dbg_ctx *dbg)
{
    step_plan  *plan;
    plan_result result;

    plan = &dbg->plan;
    if (!dbg->temp_hit || plan->wait == WAIT_NONE) {
        step_plan_cancel(dbg);
        return PLAN_FINISHED;
    }
    if (plan->wait == WAIT_RETURN && dbg_stack_pointer(dbg) < plan->return_sp) {
        result = plan_step(dbg);
        if (result == PLAN_LOOP)
            result = plan_resume(dbg, plan->target, WAIT_RETURN, plan->return_sp);
    } else {
        plan->wait = WAIT_NONE;
        result = plan_advance(dbg);
    }
    return plan_finish(dbg, result);
}

static dbg_status plan_start(dbg_ctx *dbg)
{
    plan_result result;

    result = plan_finish(dbg, plan_advance(dbg));
    switch (result) {
        case PLAN_RESUMED:
            dbg_emit(dbg, DBG_EV_RUNNING);
            dbg_settle(dbg, DBG_WAIT_STOP_MS);
            return dbg_finish(dbg, DBG_OK);
        case PLAN_FINISHED:
            dbg_emit(dbg, DBG_EV_STOPPED);
            return dbg_finish(dbg, DBG_OK);
        case PLAN_INTERRUPTED:
        case PLAN_LOOP:
            return dbg_finish(dbg, DBG_OK);
        case PLAN_FAILED:
            break;
    }
    return dbg_finish(dbg, dbg->plan.status);
}

static dbg_status plan_begin(dbg_ctx *dbg, uint8_t kind)
{
    if (dbg->state == DBG_STATE_DISCONNECTED)
        return DBG_E_DISCONNECTED;
    if (dbg->state != DBG_STATE_STOPPED)
        return DBG_E_RUNNING;
    memset(&dbg->plan, 0, sizeof dbg->plan);
    dbg->plan.kind = kind;
    dbg->plan.status = DBG_OK;
    return DBG_OK;
}

dbg_status dbg_step_line(dbg_ctx *dbg, bool into)
{
    sym_line_info line;
    dbg_status    status;

    status = plan_begin(dbg, PLAN_NONE);
    if (status != DBG_OK)
        return status;
    if (!sym_line_at(dbg, dbg_pc(dbg), &line))
        return into ? dbg_step(dbg) : dbg_step_over(dbg);
    dbg->plan.kind = PLAN_LINE;
    dbg->plan.into = into;
    dbg->plan.line = line;
    dbg->plan.func_start = sym_func_start(dbg, dbg_pc(dbg));
    return plan_start(dbg);
}

dbg_status dbg_step_to_call(dbg_ctx *dbg)
{
    dbg_status status;

    status = plan_begin(dbg, PLAN_TO_CALL);
    if (status != DBG_OK)
        return status;
    dbg->plan.skip_first = true;
    return plan_start(dbg);
}

dbg_status dbg_step_to_branch(dbg_ctx *dbg)
{
    dbg_status status;

    status = plan_begin(dbg, PLAN_TO_BRANCH);
    if (status != DBG_OK)
        return status;
    dbg->plan.skip_first = true;
    return plan_start(dbg);
}

void dbg_set_source_step(dbg_ctx *dbg, bool on)
{
    dbg->source_step = on;
}

bool dbg_get_source_step(const dbg_ctx *dbg)
{
    return dbg->source_step;
}
