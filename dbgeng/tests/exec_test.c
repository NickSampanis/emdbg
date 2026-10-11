/* dbg_exec / expression tests without a target: a dbg_ctx is put in the stopped state
 * with known registers (uses the private dbg.h). Memory and register writes need a
 * target and are covered by smoke.c. */
#include "dbg.h"

#include <stdio.h>
#include <string.h>

static char out[8192];
static int  failures;

static void on_output(void *user, dbg_out_kind kind, const char *text)
{
    (void)user;
    (void)kind;
    strncat(out, text, sizeof out - strlen(out) - 1);
}

/* Run line; check the status and that the output contains `want`. */
static void expect(dbg_ctx *dbg, const char *line, dbg_status want_st, const char *want, int src)
{
    dbg_status st;

    out[0] = '\0';
    st = dbg_exec(dbg, line);
    if (st != want_st || (want && !strstr(out, want))) {
        printf("FAIL line %d: \"%s\" -> status %d (want %d)\n  output: %s  wanted: %s\n", src,
               line, (int)st, (int)want_st, out, want ? want : "-");
        failures++;
    }
}

#define EXPECT(line, st, want) expect(dbg, line, st, want, __LINE__)

static void put_u64(FILE *file, uint64_t value)
{
    int index;

    for (index = 0; index < 8; index++)
        fputc((int)(value >> (index * 8)) & 0xff, file);
}

static void put_fixed(FILE *file, const char *text, size_t size)
{
    size_t len = strlen(text);

    fwrite(text, 1, len, file);
    while (len++ < size)
        fputc(0, file);
}

/* main: lines 10 [1000,1005) and 11 [1005,1010); helper: line 20 [1100,1120) */
static int write_ids(const char *path, int with_magic)
{
    FILE *file = fopen(path, "wb");

    if (!file)
        return 0;
    if (with_magic)
        fwrite("EIDS\1\0\0\0", 1, 8, file);
    put_u64(file, 0x2000);
    put_u64(file, 2);
    put_fixed(file, "test_source.c", 260);
    put_fixed(file, "main", 64);
    put_u64(file, 0x1000);
    put_u64(file, 2);
    put_u64(file, 0x1000); put_u64(file, 10); put_u64(file, 0x1005);
    put_u64(file, 0x1005); put_u64(file, 11); put_u64(file, 0x1010);
    put_fixed(file, "helper", 64);
    put_u64(file, 0x1100);
    put_u64(file, 1);
    put_u64(file, 0x1100); put_u64(file, 20); put_u64(file, 0x1120);
    fclose(file);
    return 1;
}

/* --- .ids version 2 ------------------------------------------------------------------- */

typedef struct blob {
    uint8_t data[8192];
    size_t  len;
} blob;

static void put_bytes(blob *b, const void *bytes, size_t len)
{
    memcpy(b->data + b->len, bytes, len);
    b->len += len;
}

static void put8(blob *b, uint8_t v)   { put_bytes(b, &v, 1); }
static void put16v(blob *b, uint16_t v) { put8(b, (uint8_t)v); put8(b, (uint8_t)(v >> 8)); }
static void put32v(blob *b, uint32_t v) { put16v(b, (uint16_t)v); put16v(b, (uint16_t)(v >> 16)); }
static void put64v(blob *b, uint64_t v) { put32v(b, (uint32_t)v); put32v(b, (uint32_t)(v >> 32)); }

static uint32_t str_add(blob *strs, const char *text)
{
    uint32_t offset = (uint32_t)strs->len;

    put_bytes(strs, text, strlen(text) + 1);
    return offset;
}

/* main [1000,1010): locals count (CFA-0x18, uint32_t) and ctx (rcx, EFI_THING *);
 * helper [1100,1120); global gTable (EFI_THING) at rva 2000. */
static int write_ids_v2(const char *path, int corrupt)
{
    static blob strs, file, func, line, type, memb, var, gvar, loc, cfa, out;
    struct { const char *tag; blob *b; uint32_t entry; } sections[] = {
        { "STRS", &strs, 1 }, { "FILE", &file, 4 }, { "FUNC", &func, 40 }, { "LINE", &line, 24 },
        { "TYPE", &type, 28 }, { "MEMB", &memb, 24 }, { "VAR ", &var, 40 }, { "GVAR", &gvar, 40 },
        { "LOC ", &loc, 32 }, { "CFA ", &cfa, 24 },
    };
    uint32_t count = (uint32_t)(sizeof sections / sizeof sections[0]);
    uint64_t offset;
    uint32_t i;
    FILE    *f;

    memset(&strs, 0, sizeof strs); memset(&file, 0, sizeof file); memset(&func, 0, sizeof func);
    memset(&line, 0, sizeof line); memset(&type, 0, sizeof type); memset(&memb, 0, sizeof memb);
    memset(&var, 0, sizeof var); memset(&gvar, 0, sizeof gvar); memset(&loc, 0, sizeof loc);
    memset(&cfa, 0, sizeof cfa); memset(&out, 0, sizeof out);
    put8(&strs, 0);

    put32v(&file, str_add(&strs, "test_v2.c"));

    put64v(&func, 0x1000); put64v(&func, 0x1010); put32v(&func, str_add(&strs, "main"));
    put32v(&func, 0); put32v(&func, 0); put32v(&func, 2); put32v(&func, 0); put32v(&func, 2);
    put64v(&func, 0x1100); put64v(&func, 0x1120); put32v(&func, str_add(&strs, "helper"));
    put32v(&func, 0); put32v(&func, 2); put32v(&func, 0); put32v(&func, 2); put32v(&func, 1);

    put64v(&line, 0x1000); put64v(&line, 0x1005); put32v(&line, 10); put32v(&line, 0);
    put64v(&line, 0x1005); put64v(&line, 0x1010); put32v(&line, 11); put32v(&line, 0);
    put64v(&line, 0x1100); put64v(&line, 0x1120); put32v(&line, 20); put32v(&line, 0);

    /* 0 none, 1 uint32_t, 2 struct EFI_THING { Value; Next }, 3 EFI_THING * */
    put8(&type, 0); put8(&type, 0); put16v(&type, 0);
    for (i = 0; i < 6; i++) put32v(&type, 0);
    put8(&type, 4); put8(&type, 0); put16v(&type, 0); put32v(&type, 4);
    put32v(&type, str_add(&strs, "uint32_t")); put32v(&type, 0); put32v(&type, 0);
    put32v(&type, 0); put32v(&type, 0);
    put8(&type, 8); put8(&type, 0); put16v(&type, 0); put32v(&type, 16);
    put32v(&type, str_add(&strs, "EFI_THING")); put32v(&type, 0); put32v(&type, 0);
    put32v(&type, 0); put32v(&type, 2);
    put8(&type, 6); put8(&type, 0); put16v(&type, 0); put32v(&type, 8);
    put32v(&type, 0); put32v(&type, 2); put32v(&type, 0); put32v(&type, 0); put32v(&type, 0);

    put32v(&memb, str_add(&strs, "Value")); put32v(&memb, 1); put64v(&memb, 0);
    put16v(&memb, 0); put16v(&memb, 0); put32v(&memb, 0);
    put32v(&memb, str_add(&strs, "Next")); put32v(&memb, 3); put64v(&memb, 8);
    put16v(&memb, 0); put16v(&memb, 0); put32v(&memb, 0);

    put8(&loc, 2); put8(&loc, 0); put16v(&loc, 0); put32v(&loc, 0); put64v(&loc, (uint64_t)-0x18);
    put64v(&loc, 0); put64v(&loc, 0);
    put8(&loc, 4); put8(&loc, 0); put16v(&loc, 0); put32v(&loc, str_add(&strs, "rcx"));
    put64v(&loc, 0); put64v(&loc, 0); put64v(&loc, 0);
    put8(&loc, 1); put8(&loc, 0); put16v(&loc, 0); put32v(&loc, 0); put64v(&loc, 0x2000);
    put64v(&loc, 0); put64v(&loc, 0);

    put32v(&var, str_add(&strs, "count")); put32v(&var, 1); put32v(&var, 2); put32v(&var, 0);
    put32v(&var, 1); put32v(&var, 0); put64v(&var, 0); put64v(&var, 0);
    put32v(&var, str_add(&strs, "ctx")); put32v(&var, 3); put32v(&var, 1); put32v(&var, 1);
    put32v(&var, 1); put32v(&var, 0); put64v(&var, 0); put64v(&var, 0);
    put32v(&gvar, str_add(&strs, "gTable")); put32v(&gvar, 2); put32v(&gvar, 4); put32v(&gvar, 2);
    put32v(&gvar, 1); put32v(&gvar, 0); put64v(&gvar, 0); put64v(&gvar, 0);

    put64v(&cfa, 0x1001); put32v(&cfa, str_add(&strs, "rsp")); put32v(&cfa, 0); put64v(&cfa, 0x10);
    put64v(&cfa, 0x1000); put32v(&cfa, str_add(&strs, "rsp")); put32v(&cfa, 0); put64v(&cfa, 8);
    put64v(&cfa, 0x1100); put32v(&cfa, str_add(&strs, "rsp")); put32v(&cfa, 0); put64v(&cfa, 8);

    put_bytes(&out, "EIDS", 4); put32v(&out, 2); put32v(&out, count); put32v(&out, 0);
    put64v(&out, 0x3000);
    offset = 24 + 24 * (uint64_t)count;
    for (i = 0; i < count; i++) {
        put_bytes(&out, sections[i].tag, 4);
        put32v(&out, sections[i].entry);
        put64v(&out, offset);
        put64v(&out, corrupt && i == 4 ? 0x100000 : sections[i].b->len);
        offset += sections[i].b->len;
    }
    for (i = 0; i < count; i++)
        put_bytes(&out, sections[i].b->data, sections[i].b->len);

    f = fopen(path, "wb");
    if (!f)
        return 0;
    fwrite(out.data, 1, out.len, f);
    fclose(f);
    return 1;
}

static void check(int ok, const char *what)
{
    if (!ok) {
        printf("FAIL: %s\n", what);
        failures++;
    }
}

static void ids_v2_tests(dbg_ctx *dbg)
{
    const sym_module *module;
    const sym_func   *func;
    const sym_type   *thing;
    int               index;

    if (!write_ids_v2("exec_test_v2.ids", 0) || !write_ids_v2("exec_test_bad.ids", 1)) {
        check(0, "cannot write the v2 test files");
        return;
    }
    EXPECT("lds exec_test_v2.ids 600000", DBG_OK,
           "2 functions, 3 lines, 3 types, 2 locals, 1 globals");
    EXPECT("ln 601007",             DBG_OK, "exec_test_v2!main+0x7");
    EXPECT("ln 601007",             DBG_OK, "test_v2.c(11)");
    EXPECT("x exec_test_v2!*",      DBG_OK, "2 symbols");
    EXPECT("lds exec_test_bad.ids 700000", DBG_E_BADARG, "corrupt .ids file (TYPE)");

    module = NULL;
    for (index = 0; index < dbg->module_count; index++)
        if (!strcmp(dbg->modules[index].name, "exec_test_v2"))
            module = &dbg->modules[index];
    check(module != NULL, "v2 module loaded");
    if (!module)
        return;
    func = module->funcs;
    check(func->start == 0x601000 && !strcmp(func->name, "main") && func->var_count == 2 &&
          func->cfa_count == 2, "main function record");
    check(!strcmp(module->vars[func->first_var].name, "count") &&
          module->locations[module->vars[0].first_loc].kind == SYM_LOC_CFA &&
          module->locations[module->vars[0].first_loc].offset == -0x18, "count: CFA-0x18");
    check(module->locations[module->vars[1].first_loc].kind == SYM_LOC_REGISTER &&
          module->locations[module->vars[1].first_loc].reg != NULL, "ctx: register rcx");
    check(module->cfas[0].reg != NULL && module->cfas[0].offset == 0x10, "CFA rule rsp+0x10");
    thing = &module->types[2];
    check(thing->kind == SYM_TYPE_STRUCT && !strcmp(thing->name, "EFI_THING") &&
          thing->member_count == 2 &&
          !strcmp(module->members[thing->first_member + 1].name, "Next") &&
          module->types[module->members[thing->first_member + 1].type].target == 2,
          "EFI_THING with a Next pointer to itself");
    check(module->pub.global_count == 1 && !strcmp(module->globals[0].name, "gTable") &&
          module->locations[module->globals[0].first_loc].offset == 0x2000, "gTable at rva 2000");
    remove("exec_test_v2.ids");
    remove("exec_test_bad.ids");
}

static void symbol_tests(dbg_ctx *dbg)
{
    dbg_source source;
    uint64_t   addr = 0;

    if (!write_ids("exec_test_sym.ids", 1) || !write_ids("exec_test_old.ids", 0)) {
        printf("FAIL: cannot write test .ids files\n");
        failures++;
        return;
    }
    EXPECT("lds exec_test_sym.ids 400000", DBG_OK, "2 functions, 3 lines");
    EXPECT("lm",                    DBG_OK, "exec_test_sym");
    EXPECT("? main",                DBG_OK, "00000000`00401000");
    EXPECT("? exec_test_sym!helper+4", DBG_OK, "00000000`00401104");
    EXPECT("? exec_test_sym",       DBG_OK, "00000000`00400000");
    EXPECT("? rax!=0",              DBG_OK, ": 1 =");
    EXPECT("? nosuch!main",         DBG_E_BADARG, "unknown symbol 'nosuch!main'");
    EXPECT("ln 401007",             DBG_OK, "exec_test_sym!main+0x7");
    EXPECT("ln 401007",             DBG_OK, "test_source.c(11) [file not found");
    EXPECT("ln 401110",             DBG_OK, "exec_test_sym!helper+0x10");
    EXPECT("ln 401500",             DBG_OK, "exec_test_sym+0x1500");
    EXPECT("ln 500000",             DBG_OK, "no symbol");

    if (!dbg_source_at(dbg, 0x40111f, &source) || source.line != 20 ||
        strcmp(source.function, "helper") || source.start != 0x401100) {
        printf("FAIL: dbg_source_at 40111f\n");
        failures++;
    }
    if (dbg_source_at(dbg, 0x401120, &source)) {
        printf("FAIL: dbg_source_at past the last line\n");
        failures++;
    }
    if (dbg_line_addr(dbg, "test_source.c", 12, &addr) != DBG_OK || addr != 0x401100) {
        printf("FAIL: dbg_line_addr 12 -> %llx\n", (unsigned long long)addr);
        failures++;
    }

    EXPECT("lds exec_test_sym 500000", DBG_OK, "unloading exec_test_sym");
    EXPECT("? main",                DBG_OK, "00000000`00501000");
    EXPECT("x exec_test_sym!m*",    DBG_OK, "00000000`00501000 exec_test_sym!main");
    EXPECT("x exec_test_sym!m*",    DBG_OK, "1 symbol\n");
    EXPECT("x *!HEL?ER",            DBG_OK, "exec_test_sym!helper");
    EXPECT("x *",                   DBG_OK, "2 symbols");
    EXPECT("x *test*!*",            DBG_OK, "2 symbols");
    EXPECT("x exec_test_sym!",      DBG_OK, "2 symbols");
    EXPECT("x nosuch!*",            DBG_OK, "0 symbols");
    EXPECT("x z*",                  DBG_OK, "0 symbols");
    EXPECT("x",                     DBG_E_BADARG, "expected a pattern");
    EXPECT("lds exec_test_old.ids 0", DBG_E_BADARG, "not an .ids or .pdb file");
    EXPECT("lds nosuch.ids 0",      DBG_E_BADARG, "symbol file not found");
    EXPECT("lds exec_test_sym.ids", DBG_E_BADARG, "expected a base address");
    EXPECT(".sympath \"a;b\"; .sympath", DBG_OK, "symbol path: a;b");
    EXPECT(".srcpath \"\"",         DBG_OK, "source path: \n");
    if (dbg_module_count(dbg) != 1) {
        printf("FAIL: module count %d\n", dbg_module_count(dbg));
        failures++;
    }
    remove("exec_test_sym.ids");
    remove("exec_test_old.ids");
}

int main(void)
{
    dbg_callbacks cb = { on_output, NULL, NULL };
    dbg_ctx      *dbg = dbg_create(&cb);

    if (!dbg)
        return 1;
    dbg->state = DBG_STATE_STOPPED;
    dbg->regs.valid = EM_RB_BIT(EM_RB_X86_CORE) | EM_RB_BIT(EM_RB_X86_SEG) | EM_RB_BIT(EM_RB_X86_CTRL);
    dbg->regs.core.rax = 0x1122334455667788ull;
    dbg->regs.core.rbx = 0x1000;
    dbg->regs.core.rip = 0x401000;
    dbg->regs.core.rflags = 0x246;
    dbg->regs.ctrl.cr3 = 0x1ab000;
    dbg->regs.seg.cs.selector = 0x10;

    /* numbers and radix */
    EXPECT("? 10",                  DBG_OK, ": 16 =");
    EXPECT("? 0n10",                DBG_OK, ": 10 =");
    EXPECT("? 0y1010",              DBG_OK, ": 10 =");
    EXPECT("? 0x1f",                DBG_OK, ": 31 =");
    EXPECT("? fffff800`00001000",   DBG_OK, "fffff800`00001000");

    /* operators and precedence */
    EXPECT("? 1+2*3",               DBG_OK, ": 7 =");
    EXPECT("? (1+2)*3",             DBG_OK, ": 9 =");
    EXPECT("? 1 << 4 | 1",          DBG_OK, ": 17 =");
    EXPECT("? 10 - 1 - 1",          DBG_OK, ": 14 =");   /* left-assoc: 0x10-1-1 */
    EXPECT("? -1",                  DBG_OK, "ffffffff`ffffffff");
    EXPECT("? ~0 == -1",            DBG_OK, ": 1 =");
    EXPECT("? 7 % 4",               DBG_OK, ": 3 =");

    /* registers */
    EXPECT("? rbx+100",             DBG_OK, "00000000`00001100");
    EXPECT("? @eax",                DBG_OK, "00000000`55667788");
    EXPECT("? ah",                  DBG_OK, ": 119 =");                /* 0x77 */
    EXPECT("? RIP",                 DBG_OK, "00000000`00401000");
    EXPECT("? cr3 >> c",            DBG_OK, ": 427 =");                /* 0x1ab */
    EXPECT("? cs",                  DBG_OK, ": 16 =");
    EXPECT("r rbx",                 DBG_OK, "rbx=0000000000001000");
    EXPECT("r",                     DBG_OK, "zr na pe nc");

    /* several commands on one line */
    EXPECT("? 1; ? 2",              DBG_OK, ": 2 =");

    /* errors, with the caret under the right column */
    EXPECT("? 10/0",                DBG_E_BADARG, "    ^ division by zero");
    EXPECT("? rax +",               DBG_E_BADARG, "expected an expression");
    EXPECT("? foo",                 DBG_E_BADARG, "    ^ unknown symbol 'foo'");
    EXPECT("? 1 2",                 DBG_E_BADARG, "unexpected '2'");
    EXPECT("? (1",                  DBG_E_BADARG, "expected ')'");
    EXPECT("zz",                    DBG_E_BADARG, "unknown command 'zz'");
    EXPECT("db401000",              DBG_E_BADARG, "unknown command");
    EXPECT("r foo",                 DBG_E_BADARG, "unknown register 'foo'");
    EXPECT("r rax 5",               DBG_E_BADARG, "expected '='");

    symbol_tests(dbg);
    ids_v2_tests(dbg);

    /* state checks */
    dbg->state = DBG_STATE_RUNNING;
    EXPECT("? rax",                 DBG_E_BADARG, "not available while the target runs");
    EXPECT("t",                     DBG_E_RUNNING, "running");
    dbg->state = DBG_STATE_DISCONNECTED;
    EXPECT("db 401000",             DBG_E_DISCONNECTED, "not connected");
    EXPECT("? 1+1",                 DBG_OK, ": 2 =");            /* works without a target */
    EXPECT("help",                  DBG_OK, "dump bytes");

    dbg_destroy(dbg);
    printf("%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures != 0;
}
