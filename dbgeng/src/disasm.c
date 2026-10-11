#include "disasm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Zydis/Zydis.h>

#include "dbg.h"

#define EPILOG_MAX_INSNS 16u

static void zydis_mode(dbg_cpu_mode mode, ZydisMachineMode *machine_mode,
                       ZydisStackWidth *stack_width)
{
    switch (mode) {
        case DBG_MODE_REAL16:
            *machine_mode = ZYDIS_MACHINE_MODE_REAL_16;
            *stack_width = ZYDIS_STACK_WIDTH_16;
            return;
        case DBG_MODE_PROT16:
            *machine_mode = ZYDIS_MACHINE_MODE_LEGACY_16;
            *stack_width = ZYDIS_STACK_WIDTH_16;
            return;
        case DBG_MODE_PROT32:
            *machine_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
            *stack_width = ZYDIS_STACK_WIDTH_32;
            return;
        case DBG_MODE_LONG64:
            break;
    }
    *machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    *stack_width = ZYDIS_STACK_WIDTH_64;
}

bool disasm_decode(dbg_cpu_mode mode, uint64_t addr, const uint8_t *buf, uint32_t len,
                   dbg_insn *out, bool *step_over)
{
    ZydisDecoder            decoder;
    ZydisFormatter          formatter;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisMachineMode        machine_mode;
    ZydisStackWidth         stack_width;
    ZyanU64                 target;
    bool                    over;

    over = false;
    memset(out, 0, sizeof *out);
    out->addr = addr;
    if (step_over)
        *step_over = false;
    if (!len)
        return false;

    zydis_mode(mode, &machine_mode, &stack_width);
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, machine_mode, stack_width)) ||
        !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buf, len, &insn, operands))) {
        out->len = 1;
        out->bytes[0] = buf[0];
        snprintf(out->text, sizeof out->text, "db %02xh", buf[0]);
        return false;
    }

    out->valid = true;
    out->len = insn.length;
    memcpy(out->bytes, buf, insn.length);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterFormatInstruction(&formatter, &insn, operands, insn.operand_count_visible,
                                    out->text, sizeof out->text, addr, ZYAN_NULL);

    switch (insn.meta.category) {
        case ZYDIS_CATEGORY_CALL:
            out->flow = DBG_FLOW_CALL;
            over = true;
            break;
        case ZYDIS_CATEGORY_COND_BR:
            out->flow = DBG_FLOW_JCC;
            break;
        case ZYDIS_CATEGORY_UNCOND_BR:
            out->flow = DBG_FLOW_JMP;
            break;
        case ZYDIS_CATEGORY_RET:
            out->flow = DBG_FLOW_RET;
            break;
        case ZYDIS_CATEGORY_INTERRUPT:
            out->flow = DBG_FLOW_INT;
            over = true;
            break;
        case ZYDIS_CATEGORY_SYSCALL:
            out->flow = DBG_FLOW_SYSCALL;
            over = true;
            break;
        default:
            out->flow = DBG_FLOW_NONE;
            break;
    }
    if (insn.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE))
        over = true;

    if ((out->flow == DBG_FLOW_CALL || out->flow == DBG_FLOW_JMP || out->flow == DBG_FLOW_JCC) &&
        insn.operand_count_visible > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
        operands[0].imm.is_relative &&
        ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &operands[0], addr, &target))) {
        out->target = target;
        out->has_target = true;
    }
    if (step_over)
        *step_over = over;
    return true;
}

static void mark_bytes(uint8_t *wildcard, uint32_t position, uint8_t offset, uint8_t bits,
                       uint8_t length)
{
    uint32_t index;

    for (index = 0; index < bits / 8u && offset + index < length; index++)
        wildcard[position + offset + index] = 1;
}

static bool address_displacement(const ZydisDecodedInstruction *insn,
                                 const ZydisDecodedOperand *operands, bool wide)
{
    uint32_t index;

    if (insn->raw.disp.size < 32)
        return false;
    if (!wide)
        return true;
    for (index = 0; index < insn->operand_count; index++) {
        if (operands[index].type != ZYDIS_OPERAND_TYPE_MEMORY)
            continue;
        if (operands[index].mem.base == ZYDIS_REGISTER_NONE ||
            operands[index].mem.base == ZYDIS_REGISTER_RIP ||
            operands[index].mem.base == ZYDIS_REGISTER_EIP)
            return true;
    }
    return false;
}

uint32_t disasm_address_mask(dbg_cpu_mode mode, const uint8_t *buf, uint32_t len,
                             uint8_t *wildcard, uint8_t *starts)
{
    ZydisDecoder            decoder;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisMachineMode        machine_mode;
    ZydisStackWidth         stack_width;
    uint32_t                position;
    uint32_t                imm_index;
    bool                    wide;

    position = 0;
    memset(wildcard, 0, len);
    memset(starts, 0, len);
    wide = mode == DBG_MODE_LONG64;
    zydis_mode(mode, &machine_mode, &stack_width);
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, machine_mode, stack_width)))
        return 0;
    while (position < len) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buf + position, len - position, &insn,
                                                 operands)))
            break;
        starts[position] = 1;
        if (address_displacement(&insn, operands, wide))
            mark_bytes(wildcard, position, insn.raw.disp.offset, insn.raw.disp.size, insn.length);
        for (imm_index = 0; imm_index < 2; imm_index++)
            if (insn.raw.imm[imm_index].size >= 32)
                mark_bytes(wildcard, position, insn.raw.imm[imm_index].offset,
                           insn.raw.imm[imm_index].size, insn.length);
        position += insn.length;
    }
    return position;
}

static bool is_rsp_operand(const ZydisDecodedOperand *operand)
{
    return operand->type == ZYDIS_OPERAND_TYPE_REGISTER && operand->reg.value == ZYDIS_REGISTER_RSP;
}

bool disasm_epilog(const uint8_t *code, uint32_t len, epilog_info *out)
{
    ZydisDecoder            decoder;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
    uint32_t                position;
    uint32_t                count;
    int64_t                 total;

    position = 0;
    total = 0;
    memset(out, 0, sizeof *out);
    out->base = "rsp";
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        return false;
    for (count = 0; count < EPILOG_MAX_INSNS && position < len; count++) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + position, len - position, &insn,
                                                 operands)))
            return false;
        if (count == 0 && insn.mnemonic == ZYDIS_MNEMONIC_ADD && is_rsp_operand(&operands[0]) &&
            operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            total += operands[1].imm.value.s;
        } else if (count == 0 && insn.mnemonic == ZYDIS_MNEMONIC_LEA &&
                   is_rsp_operand(&operands[0]) &&
                   operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                   operands[1].mem.base != ZYDIS_REGISTER_NONE &&
                   operands[1].mem.base != ZYDIS_REGISTER_RIP) {
            out->base = ZydisRegisterGetString(operands[1].mem.base);
            total = operands[1].mem.disp.value;
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_POP &&
                   operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   operands[0].size == 64) {
            if (out->pop_count < EPILOG_MAX_POPS) {
                out->pops[out->pop_count] = ZydisRegisterGetString(operands[0].reg.value);
                out->pop_offsets[out->pop_count] = total;
                out->pop_count++;
            }
            total += 8;
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_RET ||
                   (count > 0 && insn.mnemonic == ZYDIS_MNEMONIC_JMP)) {
            out->cfa_offset = total + 8;
            return out->base != NULL;
        } else {
            return false;
        }
        position += insn.length;
    }
    return false;
}

dbg_status dbg_disasm(dbg_ctx *dbg, uint64_t addr, dbg_insn *out, uint32_t max, uint32_t *count)
{
    uint8_t   *buf;
    uint32_t   size;
    uint32_t   done;
    uint32_t   pos;
    uint32_t   decoded;
    bool       valid;
    dbg_status status;

    done = 0;
    pos = 0;
    decoded = 0;
    *count = 0;
    if (max == 0)
        return DBG_OK;
    if (max > 4096)
        return DBG_E_BADARG;
    size = max * 15 + 15;
    buf = malloc(size);
    if (!buf)
        return DBG_E_NOMEM;

    status = dbg_read_mem(dbg, EM_SPACE_VIRT, addr, buf, size, &done);
    if (done == 0) {
        free(buf);
        return status == DBG_OK ? DBG_E_FAULT : status;
    }
    while (decoded < max && pos < done) {
        valid = disasm_decode(dbg_get_cpu_mode(dbg), addr + pos, buf + pos, done - pos,
                              &out[decoded], NULL);
        if (!valid && done < size && done - pos < 15)
            break;
        pos += out[decoded].len;
        decoded++;
    }
    free(buf);
    *count = decoded;
    return DBG_OK;
}
