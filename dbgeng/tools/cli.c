/* Minimal command-line frontend for dbgeng: every line goes to dbg_exec.
 *
 *   dbgeng_cli [host[:port]]      connects at startup if given ("." = 127.0.0.1:4242)
 *
 * Stop events that happen while you type are shown when you press Enter. "q" quits.
 */
#include "emdbg/dbgeng.h"

#include <stdio.h>
#include <string.h>

static void on_output(void *user, dbg_out_kind kind, const char *text)
{
    (void)user;
    if (kind == DBG_OUT_ECHO)
        return;                       /* the terminal already shows what was typed */
    fputs(text, kind == DBG_OUT_ERROR ? stderr : stdout);
}

static void on_event(void *user, const dbg_event *ev)
{
    static const char *reasons[] = { "attach", "pause", "step", "breakpoint", "watchpoint",
                                     "exception", "reset" };

    (void)user;
    if (ev->kind == DBG_EV_STOPPED)
        printf("[stopped: %s at %016llx]\n",
               ev->reason < sizeof reasons / sizeof reasons[0] ? reasons[ev->reason] : "?",
               (unsigned long long)ev->pc);
    else if (ev->kind == DBG_EV_RUNNING)
        printf("[running]\n");
    else if (ev->kind == DBG_EV_DISCONNECTED)
        printf("[disconnected]\n");
}

int main(int argc, char **argv)
{
    dbg_callbacks cb = { on_output, on_event, NULL };
    dbg_ctx      *dbg;
    char          line[1024];
    char          connect[300];

    dbg = dbg_create(&cb);
    if (!dbg)
        return 1;
    if (argc > 1) {
        snprintf(connect, sizeof connect, ".connect %s", strcmp(argv[1], ".") ? argv[1] : "");
        dbg_exec(dbg, connect);
    }

    for (;;) {
        dbg_poll(dbg);
        printf(dbg_get_state(dbg) == DBG_STATE_RUNNING ? "(running)> " : "> ");
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin))
            break;
        if (!strcmp(line, "q\n") || !strcmp(line, "q"))
            break;
        dbg_poll(dbg);
        dbg_exec(dbg, line);
    }
    dbg_destroy(dbg);
    return 0;
}
