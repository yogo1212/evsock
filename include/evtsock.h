#ifndef __EVT_SOCK_H
#define __EVT_SOCK_H

#include <stdbool.h>

#include <event2/bufferevent.h>

struct evtsock;
typedef struct evtsock evtsock_t;

typedef struct bufferevent *(*evtsock_conn_cb_t)(void *conn_ctx);

evtsock_t *evtsock_new(
	// this is used to get new connections to the proxy
	evtsock_conn_cb_t conn_cb,
	void *conn_ctx
);
void evtsock_free(evtsock_t *esock);

typedef enum {
	EVTSOCK_CMD_CONNECT_TCP = 1,
	// TODO implement!
	// EVTSOCK_CMD_BIND_TCP,
	/* only available for SOCKS5 */
	EVTSOCK_CMD_BIND_UDP,
} evtsock_command_t;

typedef enum {
	EVTSOCK_EVENT_SUCCESS = 0,
	EVTSOCK_EVENT_FAILED, // the server said it..
	EVTSOCK_EVENT_NO_IDENTD,
	EVTSOCK_EVENT_IDENTD_ERR,
	EVTSOCK_EVENT_BAD_INPUT,
	EVTSOCK_EVENT_USER_ABORT,
	EVTSOCK_EVENT_READ_ERROR,
	EVTSOCK_EVENT_SHORT_READ,
	EVTSOCK_EVENT_EOF,
	EVTSOCK_EVENT_PROTO,
	EVTSOCK_EVENT_SOCKET_ERR,
	EVTSOCK_EVENT_TIMEOUT,
} evtsock_event_t;

typedef struct {
	struct bufferevent *bev; // for socks4
	struct sockaddr_storage ss;
} evtsock_res_t;

typedef void (*evtsock_cb_t)(evtsock_event_t evt, void *ctx, evtsock_res_t *res);

struct socks4_request;
typedef struct socks4_request socks4_request_t;

void socks4_request_abort(socks4_request_t *r);

/* NULL indicates ouch */
socks4_request_t *evtsock4_connect_ip(evtsock_t *esock, const struct sockaddr_in *sin, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx);
/* requires SOCKS4a */
socks4_request_t *evtsock4_connect_hostname(evtsock_t *esock, const char *hostname, uint16_t port, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx);

#endif
