#define _POSIX_C_SOURCE 200809L

#include "plat.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

int plat_net_init(void)
{
    return 0;
}

void plat_net_cleanup(void)
{
}

static int wait_connected(int sock, uint32_t timeout_ms)
{
    fd_set         write_set;
    struct timeval timeout;
    int            error;
    socklen_t      error_len;

    error = 0;
    error_len = sizeof error;
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);
    timeout.tv_sec  = (time_t)(timeout_ms / 1000);
    timeout.tv_usec = (suseconds_t)(timeout_ms % 1000) * 1000;
    if (select(sock + 1, NULL, &write_set, NULL, &timeout) <= 0)
        return -1;
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error != 0)
        return -1;
    return 0;
}

plat_sock plat_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms)
{
    struct addrinfo  hints;
    struct addrinfo *results;
    struct addrinfo *addr;
    char             service[8];
    int              sock;
    int              flags;
    int              nodelay;

    results = NULL;
    sock = -1;
    nodelay = 1;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(service, sizeof service, "%u", (unsigned)port);
    if (getaddrinfo(host, service, &hints, &results) != 0)
        return PLAT_SOCK_INVALID;

    for (addr = results; addr; addr = addr->ai_next) {
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock < 0)
            continue;
        flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        if (connect(sock, addr->ai_addr, addr->ai_addrlen) == 0 ||
            (errno == EINPROGRESS && wait_connected(sock, timeout_ms) == 0)) {
            fcntl(sock, F_SETFL, flags);
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof nodelay);
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(results);
    return sock < 0 ? PLAT_SOCK_INVALID : (plat_sock)sock;
}

int plat_sock_send(plat_sock sock, const void *buf, uint32_t len)
{
    const char *data;
    ssize_t     sent;

    data = (const char *)buf;
    while (len) {
        sent = send((int)sock, data, len, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0)
            return -1;
        data += sent;
        len -= (uint32_t)sent;
    }
    return 0;
}

int plat_sock_recv(plat_sock sock, void *buf, uint32_t len, uint32_t timeout_ms)
{
    fd_set         read_set;
    struct timeval timeout;
    ssize_t        received;
    int            ready;

    FD_ZERO(&read_set);
    FD_SET((int)sock, &read_set);
    timeout.tv_sec  = (time_t)(timeout_ms / 1000);
    timeout.tv_usec = (suseconds_t)(timeout_ms % 1000) * 1000;
    ready = select((int)sock + 1, &read_set, NULL, NULL, &timeout);
    if (ready < 0)
        return errno == EINTR ? 0 : -1;
    if (ready == 0)
        return 0;
    received = recv((int)sock, buf, len, 0);
    return received > 0 ? (int)received : -1;
}

void plat_sock_close(plat_sock sock)
{
    if (sock != PLAT_SOCK_INVALID)
        close((int)sock);
}

uint64_t plat_time_ms(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

int plat_list_dir(const char *dir, plat_dir_fn fn, void *user)
{
    DIR           *handle;
    struct dirent *entry;
    struct stat    info;
    char           path[4096];

    handle = opendir(dir);
    if (!handle)
        return -1;
    while ((entry = readdir(handle)) != NULL) {
        if (snprintf(path, sizeof path, "%s/%s", dir, entry->d_name) >= (int)sizeof path)
            continue;
        if (stat(path, &info) == 0 && S_ISREG(info.st_mode))
            fn(user, entry->d_name);
    }
    closedir(handle);
    return 0;
}
