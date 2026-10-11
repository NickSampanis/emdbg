#ifndef DBGENG_PLAT_H
#define DBGENG_PLAT_H

#include <stdint.h>

typedef intptr_t plat_sock;
#define PLAT_SOCK_INVALID ((plat_sock)-1)

int       plat_net_init(void);
void      plat_net_cleanup(void);

plat_sock plat_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms);

int       plat_sock_send(plat_sock sock, const void *buf, uint32_t len);

int       plat_sock_recv(plat_sock sock, void *buf, uint32_t len, uint32_t timeout_ms);

void      plat_sock_close(plat_sock sock);

uint64_t  plat_time_ms(void);

typedef void (*plat_dir_fn)(void *user, const char *name);

int       plat_list_dir(const char *dir, plat_dir_fn fn, void *user);

#endif
