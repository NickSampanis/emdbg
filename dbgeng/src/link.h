#ifndef DBGENG_LINK_H
#define DBGENG_LINK_H

#include <stdbool.h>
#include <stdint.h>

#include "emdbg/dbgeng.h"
#include "plat.h"

#define LINK_MAX_PAYLOAD  0x10000u

typedef void (*link_event_fn)(void *user, uint16_t type, const uint8_t *payload, uint32_t len);

typedef struct dbg_link {
    plat_sock     sock;
    bool          open;
    uint32_t      next_seq;
    uint32_t      peer_max;
    uint32_t      rx_have;
    uint8_t      *rx;
    uint8_t      *tx;
    link_event_fn on_event;
    void         *user;
} dbg_link;

dbg_status link_open(dbg_link *link, const char *host, uint16_t port, uint32_t timeout_ms,
                     link_event_fn on_event, void *user);
void       link_close(dbg_link *link);

dbg_status link_call(dbg_link *link, uint16_t type, const void *req, uint32_t req_len,
                     const void *tail, uint32_t tail_len, void *reply, uint32_t cap,
                     uint32_t *reply_len, uint32_t timeout_ms);

void       link_pump(dbg_link *link, uint32_t timeout_ms);

#endif
