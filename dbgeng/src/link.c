#include "link.h"

#include <stdlib.h>
#include <string.h>

#include "emstub/proto.h"

static dbg_status from_em(uint8_t status)
{
    switch (status) {
        case EM_OK:
            return DBG_OK;
        case EM_E_UNSUPPORTED:
            return DBG_E_UNSUPPORTED;
        case EM_E_BADARG:
            return DBG_E_BADARG;
        case EM_E_FAULT:
            return DBG_E_FAULT;
        case EM_E_PARTIAL:
            return DBG_E_PARTIAL;
        case EM_E_RUNNING:
            return DBG_E_RUNNING;
    }
    return DBG_E_PROTOCOL;
}

static void drop(dbg_link *link)
{
    plat_sock_close(link->sock);
    link->sock = PLAT_SOCK_INVALID;
    link->open = false;
    link->rx_have = 0;
}

dbg_status link_open(dbg_link *link, const char *host, uint16_t port, uint32_t timeout_ms,
                     link_event_fn on_event, void *user)
{
    memset(link, 0, sizeof *link);
    link->sock = PLAT_SOCK_INVALID;
    link->rx = malloc(sizeof(em_hdr) + LINK_MAX_PAYLOAD);
    link->tx = malloc(sizeof(em_hdr) + LINK_MAX_PAYLOAD);
    if (!link->rx || !link->tx) {
        link_close(link);
        return DBG_E_NOMEM;
    }
    link->sock = plat_tcp_connect(host, port, timeout_ms);
    if (link->sock == PLAT_SOCK_INVALID) {
        link_close(link);
        return DBG_E_CONNECT;
    }
    link->open     = true;
    link->next_seq = 1;
    link->peer_max = EM_MIN_PAYLOAD;
    link->on_event = on_event;
    link->user     = user;
    return DBG_OK;
}

void link_close(dbg_link *link)
{
    plat_sock_close(link->sock);
    free(link->rx);
    free(link->tx);
    memset(link, 0, sizeof *link);
    link->sock = PLAT_SOCK_INVALID;
}

static int recv_packet(dbg_link *link, uint32_t timeout_ms)
{
    em_hdr   hdr;
    uint32_t need;
    uint64_t deadline;
    uint64_t now;
    int      received;

    deadline = plat_time_ms() + timeout_ms;
    for (;;) {
        need = (uint32_t)sizeof hdr;
        if (link->rx_have >= sizeof hdr) {
            memcpy(&hdr, link->rx, sizeof hdr);
            if (hdr.magic != EM_MAGIC || hdr.len > LINK_MAX_PAYLOAD ||
                (hdr.kind != EM_KIND_REPLY && hdr.kind != EM_KIND_EVENT)) {
                drop(link);
                return -1;
            }
            need += hdr.len;
            if (link->rx_have == need) {
                link->rx_have = 0;
                if (hdr.len && em_crc32(0, link->rx + sizeof hdr, hdr.len) != hdr.crc) {
                    drop(link);
                    return -1;
                }
                return 1;
            }
        }

        now = plat_time_ms();
        received = plat_sock_recv(link->sock, link->rx + link->rx_have, need - link->rx_have,
                                  now < deadline ? (uint32_t)(deadline - now) : 0);
        if (received < 0) {
            drop(link);
            return -1;
        }
        if (received == 0)
            return 0;
        link->rx_have += (uint32_t)received;
    }
}

static void dispatch_event(dbg_link *link, const em_hdr *hdr)
{
    if (link->on_event)
        link->on_event(link->user, hdr->type, link->rx + sizeof *hdr, hdr->len);
}

dbg_status link_call(dbg_link *link, uint16_t type, const void *req, uint32_t req_len,
                     const void *tail, uint32_t tail_len, void *reply, uint32_t cap,
                     uint32_t *reply_len, uint32_t timeout_ms)
{
    em_hdr   hdr;
    uint32_t seq;
    uint32_t len;
    uint32_t copied;
    uint64_t deadline;
    uint64_t now;
    int      result;

    len = req_len + tail_len;
    if (reply_len)
        *reply_len = 0;
    if (!link->open)
        return DBG_E_DISCONNECTED;
    if (len > link->peer_max || len > LINK_MAX_PAYLOAD)
        return DBG_E_BADARG;

    seq = link->next_seq++;
    if (link->next_seq == 0)
        link->next_seq = 1;

    if (req_len)
        memcpy(link->tx + sizeof hdr, req, req_len);
    if (tail_len)
        memcpy(link->tx + sizeof hdr + req_len, tail, tail_len);
    hdr.magic  = EM_MAGIC;
    hdr.type   = type;
    hdr.kind   = EM_KIND_REQ;
    hdr.status = 0;
    hdr.seq    = seq;
    hdr.len    = len;
    hdr.crc    = len ? em_crc32(0, link->tx + sizeof hdr, len) : 0;
    memcpy(link->tx, &hdr, sizeof hdr);
    if (plat_sock_send(link->sock, link->tx, (uint32_t)sizeof hdr + len) < 0) {
        drop(link);
        return DBG_E_DISCONNECTED;
    }

    deadline = plat_time_ms() + timeout_ms;
    for (;;) {
        now = plat_time_ms();
        result = recv_packet(link, now < deadline ? (uint32_t)(deadline - now) : 0);
        if (result < 0)
            return DBG_E_DISCONNECTED;
        if (result == 0)
            return DBG_E_TIMEOUT;

        memcpy(&hdr, link->rx, sizeof hdr);
        if (hdr.kind == EM_KIND_EVENT) {
            dispatch_event(link, &hdr);
            if (!link->open)
                return DBG_E_DISCONNECTED;
            continue;
        }
        if (hdr.seq != seq)
            continue;
        if (hdr.type != type)
            return DBG_E_PROTOCOL;

        copied = hdr.len < cap ? hdr.len : cap;
        if (reply && copied)
            memcpy(reply, link->rx + sizeof hdr, copied);
        if (reply_len)
            *reply_len = reply ? copied : 0;
        return from_em(hdr.status);
    }
}

void link_pump(dbg_link *link, uint32_t timeout_ms)
{
    em_hdr hdr;

    while (link->open && recv_packet(link, timeout_ms) > 0) {
        memcpy(&hdr, link->rx, sizeof hdr);
        if (hdr.kind == EM_KIND_EVENT)
            dispatch_event(link, &hdr);
        timeout_ms = 0;
    }
}
