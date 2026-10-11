/* End-to-end check of dbgeng against a running fake_target:
 *
 *   emstub_fake_target            (in one terminal)
 *   dbgeng_smoke [host] [port]    (in another)
 */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "dbg.h"          /* private: force_soft_bp, temp_bp */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(unsigned ms) { Sleep(ms); }
#else
#include <time.h>
static void sleep_ms(unsigned ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}
#endif

static int            failures;
static int            stops;
static em_stop_reason last_reason;
static uint32_t       last_bp;

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

static void on_output(void *user, dbg_out_kind kind, const char *text)
{
    (void)user;
    printf("%s%s", kind == DBG_OUT_ERROR ? "[error] " : kind == DBG_OUT_TARGET ? "[target] " : "",
           text);
}

static void on_event(void *user, const dbg_event *ev)
{
    static const char *names[] = { "connected", "disconnected", "running", "stopped" };

    (void)user;
    if (ev->kind == DBG_EV_STOPPED) {
        stops++;
        last_reason = ev->reason;
        last_bp = ev->bp_id;
        printf("event: stopped, reason %d, pc %016llX\n", (int)ev->reason,
               (unsigned long long)ev->pc);
    } else {
        printf("event: %s\n", names[ev->kind]);
    }
}

/* Poll until the target stops (at most 2 s). */
static int wait_stop(dbg_ctx *dbg)
{
    int i;

    for (i = 0; i < 200 && dbg_get_state(dbg) != DBG_STATE_STOPPED; i++) {
        dbg_poll(dbg);
        sleep_ms(10);
    }
    return dbg_get_state(dbg) == DBG_STATE_STOPPED;
}

/* Byte at a physical address: shows a planted 0xCC, unlike virtual reads. */
static uint8_t phys_byte(dbg_ctx *dbg, uint64_t pa)
{
    uint8_t b = 0;

    dbg_read_mem(dbg, EM_SPACE_PHYS, pa, &b, 1, NULL);
    return b;
}

int main(int argc, char **argv)
{
    static const uint8_t checksum_start[] = { 0x31, 0xC0, 0x85, 0xF6 };
    dbg_callbacks        cb = { on_output, on_event, NULL };
    const char          *host = argc > 1 ? argv[1] : "127.0.0.1";
    uint16_t             port = (uint16_t)(argc > 2 ? atoi(argv[2]) : 4242);
    const em_x86_regs   *r;
    dbg_ctx             *dbg;
    uint8_t              buf[64];
    uint8_t              pattern[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4 };
    uint32_t             done;
    uint32_t             n;
    dbg_insn             insns[3];
    uint32_t             id;
    int                  i;

    dbg = dbg_create(&cb);
    CHECK(dbg != NULL);
    if (!dbg)
        return 1;

    if (dbg_connect(dbg, host, port) != DBG_OK) {
        printf("is emstub_fake_target running?\n");
        return 1;
    }
    CHECK(dbg_get_state(dbg) == DBG_STATE_STOPPED);          /* fake target starts stopped */
    CHECK(dbg_target(dbg) && dbg_target(dbg)->cpu_count == 1);
    CHECK(dbg_target_supports(dbg, EM_CMD_BP_SET));
    CHECK(!dbg_target_supports(dbg, EM_CMD_READ_MSR));

    r = dbg_regs(dbg);
    CHECK(r && r->core.rip == 0x401040 && r->ctrl.cr3 == 0x1000 && r->seg.cs.selector == 0x10);

    /* Virtual read through the stub's page walker. */
    CHECK(dbg_read_mem(dbg, EM_SPACE_VIRT, 0x401000, buf, 4, &done) == DBG_OK && done == 4);
    CHECK(!memcmp(buf, checksum_start, 4));
    CHECK(dbg_read_mem(dbg, EM_SPACE_VIRT, 0x900000, buf, 4, &done) == DBG_E_FAULT);

    /* Write + read back in the data page's spare area. */
    CHECK(dbg_write_mem(dbg, EM_SPACE_VIRT, 0x402100, pattern, sizeof pattern, &done) == DBG_OK);
    CHECK(dbg_read_mem(dbg, EM_SPACE_VIRT, 0x402100, buf, sizeof pattern, &done) == DBG_OK);
    CHECK(!memcmp(buf, pattern, sizeof pattern));

    /* Single steps: start -> main -> sub rsp -> lea rdi. */
    CHECK(dbg_step(dbg) == DBG_OK && (r = dbg_regs(dbg)) && r->core.rip == 0x401020);
    CHECK(dbg_step(dbg) == DBG_OK && (r = dbg_regs(dbg)) && r->core.rip == 0x401024);
    CHECK(dbg_step(dbg) == DBG_OK && (r = dbg_regs(dbg)) && r->core.rip == 0x40102B &&
          r->core.rdi == 0x402000);

    /* Free run, then pause. */
    CHECK(dbg_continue(dbg) == DBG_OK && dbg_get_state(dbg) == DBG_STATE_RUNNING);
    CHECK(dbg_regs(dbg) == NULL);
    CHECK(dbg_step(dbg) == DBG_E_RUNNING);
    for (i = 0; i < 20; i++) {
        dbg_poll(dbg);
        sleep_ms(10);
    }
    CHECK(dbg_read_mem(dbg, EM_SPACE_VIRT, 0x401000, buf, 4, &done) == DBG_OK);  /* while running */
    CHECK(dbg_pause(dbg) == DBG_OK && dbg_get_state(dbg) == DBG_STATE_STOPPED);
    r = dbg_regs(dbg);
    CHECK(r && r->core.rip >= 0x401000 && r->core.rip < 0x401050);

    CHECK(dbg_monitor(dbg, "info") == DBG_OK);

    /* Disassembly of checksum(). */
    CHECK(dbg_get_cpu_mode(dbg) == DBG_MODE_LONG64);
    CHECK(dbg_disasm(dbg, 0x401000, insns, 3, &n) == DBG_OK && n == 3);
    CHECK(!strcmp(insns[0].text, "xor eax, eax") && insns[0].len == 2);
    CHECK(insns[2].flow == DBG_FLOW_JCC && insns[2].has_target && insns[2].target == 0x401017);

    /* Step over "call main" with the stub's breakpoint, then with a 0xCC in memory. */
    for (i = 0; i < 2; i++) {
        dbg->force_soft_bp = i == 1;
        CHECK(dbg_exec(dbg, "r rip=401040; r rsp=40ff00; r rax=0") == DBG_OK);
        CHECK(dbg_pc(dbg) == 0x401040);
        CHECK(dbg_step_over(dbg) == DBG_OK && dbg_get_state(dbg) == DBG_STATE_STOPPED);
        r = dbg_regs(dbg);
        CHECK(r && r->core.rip == 0x401045 && r->core.rax == 2 && r->core.rsp == 0x40FF00);
        CHECK(dbg_read_mem(dbg, EM_SPACE_VIRT, 0x401045, buf, 1, &done) == DBG_OK && buf[0] == 0xEB);
        CHECK(!dbg->temp_bp.pub.planted);
    }
    /* Step over a plain instruction is a single step. */
    CHECK(dbg_step_over(dbg) == DBG_OK && dbg_pc(dbg) == 0x401040);

    /* User breakpoints, through the stub and then as 0xCC. 0x401008 (loop body) is at
     * physical 0x11008; its first byte is 0x0F. */
    for (i = 0; i < 2; i++) {
        dbg->force_soft_bp = i == 1;
        CHECK(dbg_exec(dbg, "bc *; r rip=401040; r rsp=40ff00") == DBG_OK);
        CHECK(dbg_bp_add(dbg, EM_BP_EXEC, 0x401008, 1, &id) == DBG_OK);
        CHECK(!strcmp(dbg_bp_where(dbg, id), i ? "int3" : "stub"));
        CHECK(phys_byte(dbg, 0x11008) == (i ? 0xCC : 0x0F));
        CHECK(dbg_read_mem(dbg, EM_SPACE_VIRT, 0x401008, buf, 1, &done) == DBG_OK && buf[0] == 0x0F);
        CHECK(dbg_disasm(dbg, 0x401008, insns, 1, &n) == DBG_OK && !strncmp(insns[0].text, "movzx", 5));

        /* hit, then resume from it: the loop comes round and hits again */
        CHECK(dbg_continue(dbg) == DBG_OK && wait_stop(dbg));
        CHECK(dbg_pc(dbg) == 0x401008 && last_reason == EM_STOP_BREAKPOINT && last_bp == id);
        CHECK(dbg_continue(dbg) == DBG_OK && wait_stop(dbg));
        CHECK(dbg_pc(dbg) == 0x401008 && dbg_bp_find(dbg, 0x401008)->hits == 2);

        /* stepping from a breakpoint runs the instruction and keeps the breakpoint */
        CHECK(dbg_step(dbg) == DBG_OK && dbg_pc(dbg) == 0x40100C);
        CHECK(phys_byte(dbg, 0x11008) == (i ? 0xCC : 0x0F));

        /* step over a call that has a breakpoint on it */
        CHECK(dbg_exec(dbg, "bc *; bp 401030; r rip=401040; r rsp=40ff00") == DBG_OK);
        CHECK(dbg_continue(dbg) == DBG_OK && wait_stop(dbg) && dbg_pc(dbg) == 0x401030);
        CHECK(dbg_step_over(dbg) == DBG_OK && dbg_pc(dbg) == 0x401035);
        r = dbg_regs(dbg);
        CHECK(r && r->core.rax == 2 && last_reason == EM_STOP_STEP);
        CHECK(dbg_bp_find(dbg, 0x401030) && dbg_bp_find(dbg, 0x401030)->planted);
        CHECK(phys_byte(dbg, 0x11030) == (i ? 0xCC : 0xE8));

        /* writing over a 0xCC breakpoint updates its saved byte, not the 0xCC */
        buf[0] = 0xE8;
        CHECK(dbg_write_mem(dbg, EM_SPACE_VIRT, 0x401030, buf, 1, &done) == DBG_OK);
        CHECK(phys_byte(dbg, 0x11030) == (i ? 0xCC : 0xE8));

        /* removing it restores the code */
        CHECK(dbg_exec(dbg, "bc *") == DBG_OK && dbg_bp_count(dbg) == 0);
        CHECK(phys_byte(dbg, 0x11030) == 0xE8);
    }
    dbg->force_soft_bp = false;

    /* Data breakpoint: the fake target has no watchpoints, so it goes into DR0 / DR7. */
    CHECK(dbg_exec(dbg, "ba w 8 40ff00") == DBG_OK);
    r = dbg_regs(dbg);
    CHECK(r && r->ctrl.dr0 == 0x40FF00 && (r->ctrl.dr7 & 1) && ((r->ctrl.dr7 >> 16) & 0xF) == 0x9);
    CHECK(dbg_exec(dbg, "bc *") == DBG_OK && r->ctrl.dr0 == 0 && !(r->ctrl.dr7 & 1));

    dbg_disconnect(dbg);
    CHECK(dbg_get_state(dbg) == DBG_STATE_DISCONNECTED);
    CHECK(dbg_step(dbg) == DBG_E_DISCONNECTED);
    dbg_destroy(dbg);

    printf("%d stop events\n%s (%d failures)\n", stops, failures ? "FAILED" : "ALL PASSED", failures);
    return failures != 0;
}
