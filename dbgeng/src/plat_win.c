#include "plat.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <string.h>

int plat_net_init(void)
{
    WSADATA wsa_data;

    return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0 ? 0 : -1;
}

void plat_net_cleanup(void)
{
    WSACleanup();
}

static int wait_connected(SOCKET sock, uint32_t timeout_ms)
{
    fd_set         write_set;
    fd_set         error_set;
    struct timeval timeout;
    int            error;
    int            error_len;

    error = 0;
    error_len = sizeof error;
    FD_ZERO(&write_set);
    FD_ZERO(&error_set);
    FD_SET(sock, &write_set);
    FD_SET(sock, &error_set);
    timeout.tv_sec  = (long)(timeout_ms / 1000);
    timeout.tv_usec = (long)(timeout_ms % 1000) * 1000;
    if (select(0, NULL, &write_set, &error_set, &timeout) <= 0 || FD_ISSET(sock, &error_set))
        return -1;
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&error, &error_len) != 0 || error != 0)
        return -1;
    return 0;
}

plat_sock plat_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms)
{
    struct addrinfo  hints;
    struct addrinfo *results;
    struct addrinfo *addr;
    char             service[8];
    SOCKET           sock;
    u_long           nonblock;
    BOOL             nodelay;

    results = NULL;
    sock = INVALID_SOCKET;
    nodelay = TRUE;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(service, sizeof service, "%u", (unsigned)port);
    if (getaddrinfo(host, service, &hints, &results) != 0)
        return PLAT_SOCK_INVALID;

    for (addr = results; addr; addr = addr->ai_next) {
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock == INVALID_SOCKET)
            continue;
        nonblock = 1;
        ioctlsocket(sock, FIONBIO, &nonblock);
        if (connect(sock, addr->ai_addr, (int)addr->ai_addrlen) == 0 ||
            (WSAGetLastError() == WSAEWOULDBLOCK && wait_connected(sock, timeout_ms) == 0)) {
            nonblock = 0;
            ioctlsocket(sock, FIONBIO, &nonblock);
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof nodelay);
            break;
        }
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
    freeaddrinfo(results);
    return sock == INVALID_SOCKET ? PLAT_SOCK_INVALID : (plat_sock)sock;
}

int plat_sock_send(plat_sock sock, const void *buf, uint32_t len)
{
    const char *data;
    int         sent;

    data = (const char *)buf;
    while (len) {
        sent = send((SOCKET)sock, data, (int)len, 0);
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
    int            result;

    FD_ZERO(&read_set);
    FD_SET((SOCKET)sock, &read_set);
    timeout.tv_sec  = (long)(timeout_ms / 1000);
    timeout.tv_usec = (long)(timeout_ms % 1000) * 1000;
    result = select(0, &read_set, NULL, NULL, &timeout);
    if (result < 0)
        return -1;
    if (result == 0)
        return 0;
    result = recv((SOCKET)sock, (char *)buf, (int)len, 0);
    return result > 0 ? result : -1;
}

void plat_sock_close(plat_sock sock)
{
    if (sock != PLAT_SOCK_INVALID)
        closesocket((SOCKET)sock);
}

uint64_t plat_time_ms(void)
{
    return GetTickCount64();
}

int plat_list_dir(const char *dir, plat_dir_fn fn, void *user)
{
    WIN32_FIND_DATAA find_data;
    HANDLE           find;
    char             pattern[MAX_PATH + 3];

    if (snprintf(pattern, sizeof pattern, "%s/*", dir) >= (int)sizeof pattern)
        return -1;
    find = FindFirstFileA(pattern, &find_data);
    if (find == INVALID_HANDLE_VALUE)
        return -1;
    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            fn(user, find_data.cFileName);
    } while (FindNextFileA(find, &find_data));
    FindClose(find);
    return 0;
}
