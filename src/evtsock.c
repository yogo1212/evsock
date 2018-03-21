#include <stdlib.h>

#include "internal.h"

#include "evtsock.h"

struct evtsock{
	struct event_base *base;
	evtsock_conn_cb_t conn_cb;
	void *conn_ctx;
};

evtsock_t *evtsock_new(evtsock_conn_cb_t conn_cb, void *conn_ctx)
{
	evtsock_t *res = malloc(sizeof(evtsock_t));

	res->conn_cb = conn_cb;
	res->conn_ctx = conn_ctx;

	return res;
}

void evtsock_free(evtsock_t *esock)
{
	free(esock);
}

socks4_request_t *evtsock4_connect_hostname(evtsock_t *esock, const char *hostname, uint16_t port, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx)
{
	struct bufferevent *bev = esock->conn_cb(esock->conn_ctx);
	return socks4_host(bev, hostname, port, cmd, cb, ctx);
}

socks4_request_t *evtsock4_connect_ip(evtsock_t *esock, const struct sockaddr_in *sin, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx)
{
	struct bufferevent *bev = esock->conn_cb(esock->conn_ctx);
	return socks4_ip(bev, sin, cmd, cb, ctx);
}