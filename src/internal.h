#ifndef INTERNAL_H
#define INTERNAL_H

#include "evtsock.h"

socks4_request_t *socks4_host(struct bufferevent *bev, const char *hostname, uint16_t port, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx);
socks4_request_t *socks5_host(struct bufferevent *bev, const char *hostname, uint16_t port, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx);

socks4_request_t *socks4_ip(struct bufferevent *bev, const struct sockaddr_in *sin, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx);
socks4_request_t *socks5_ip(struct bufferevent *bev, const struct sockaddr *s, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx);

#endif