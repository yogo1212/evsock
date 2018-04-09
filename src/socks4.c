#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/event.h>

#include "socks4_internal.h"

#include "internal.h"

struct socks4_request {
	evtsock_cb_t cb;
	void *ctx;
	struct bufferevent *bev;
};

static void release_request(socks4_request_t *r, evtsock_event_t evt)
{
	bufferevent_free(r->bev);
	r->cb(evt, r->ctx, NULL);
	free(r);
}

void socks4_request_abort(socks4_request_t *r)
{
	release_request(r, EVTSOCK_EVENT_USER_ABORT);
}

static void socks4_event(struct bufferevent *bev, short what, void *ctx)
{
	(void) bev;

	socks4_request_t *r = ctx;

	if (what & BEV_EVENT_EOF) {
		release_request(r, EVTSOCK_EVENT_EOF);
		return;
	}

	if (what & BEV_EVENT_ERROR) {
		release_request(r, EVTSOCK_EVENT_SOCKET_ERR);
		return;
	}

	if (what & BEV_EVENT_TIMEOUT) {
		release_request(r, EVTSOCK_EVENT_TIMEOUT);
		return;
	}
}

static socks4_request_t *create_request(struct bufferevent *bev, bufferevent_data_cb read_cb, evtsock_cb_t cb, void *ctx)
{
	socks4_request_t *res = malloc(sizeof(socks4_request_t));
	res->bev = bev;
	res->cb = cb;
	res->ctx = ctx;

	// TODO make sure there's no data from the real destination in the buffer
	bufferevent_setwatermark(bev, EV_READ, sizeof(socks4_resp_hdr_t), sizeof(socks4_resp_hdr_t));
	bufferevent_setcb(bev, read_cb, NULL, socks4_event, res);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	struct timeval read_tv = { 30, 0 };
	struct timeval write_tv = { 30, 0 };
	bufferevent_set_timeouts(bev, &read_tv, &write_tv);

	return res;
}

static void socks4_connect_read(struct bufferevent *bev, void *ctx)
{
	socks4_request_t *r = ctx;

	struct evbuffer *evb = bufferevent_get_input(bev);

	socks4_resp_hdr_t hdr;
	ssize_t rlen = evbuffer_remove(evb, &hdr, sizeof(hdr));
	if (rlen == -1) {
		release_request(r, EVTSOCK_EVENT_READ_ERROR);
		return;
	}
	else if (rlen != sizeof(hdr)) {
		release_request(r, EVTSOCK_EVENT_SHORT_READ);
		return;
	}

	if (hdr.version != SOCKS4_RESP_VERSION) {
		release_request(r, EVTSOCK_EVENT_PROTO);
		return;
	}

	switch (hdr.status) {
	case SOCKS4_RESP_STATUS_GRANTED:
		break;
	case SOCKS4_RESP_STATUS_FAILED:
		release_request(r, EVTSOCK_EVENT_FAILED);
		return;
	case SOCKS4_RESP_STATUS_NO_IDENTD:
		release_request(r, EVTSOCK_EVENT_NO_IDENTD);
		return;
	case SOCKS4_RESP_STATUS_IDENTD_ERR:
		release_request(r, EVTSOCK_EVENT_IDENTD_ERR);
		return;
	default:
		release_request(r, EVTSOCK_EVENT_PROTO);
		return;
	}

	evtsock_res_t res;
	struct sockaddr_in *sin = (struct sockaddr_in *) &res.ss;
	sin->sin_family = AF_INET;
	sin->sin_port = ntohs(hdr.port);
	sin->sin_addr.s_addr = ntohl(hdr.ip);

	res.bev = bev;
	bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	bufferevent_setwatermark(bev, EV_READ, 0, 0);
	bufferevent_disable(bev, EV_READ | EV_WRITE);

	r->cb(EVTSOCK_EVENT_SUCCESS, r->ctx, &res);
	free(r);
}

socks4_request_t *socks4_host(struct bufferevent *bev, const char *hostname, uint16_t port, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx)
{
	if (cmd == EVTSOCK_CMD_BIND_UDP) {
		cb(EVTSOCK_EVENT_BAD_INPUT, ctx, NULL);
		return NULL;
	}

	socks4_req_hdr_t hdr = {
		SOCKS4_REQ_VERSION,
		cmd, htons(port), htonl(0x0000000C),
		0
	};

	struct evbuffer *evb = evbuffer_new();
	evbuffer_add(evb, &hdr, sizeof(hdr));
	evbuffer_add(evb, hostname, strlen(hostname) + 1);
	bufferevent_write_buffer(bev, evb);
	evbuffer_free(evb);

	return create_request(bev, socks4_connect_read, cb, ctx);
}

socks4_request_t *socks4_ip(struct bufferevent *bev, const struct sockaddr_in *sin, evtsock_command_t cmd, evtsock_cb_t cb, void *ctx)
{
	if (cmd == EVTSOCK_CMD_BIND_UDP) {
		cb(EVTSOCK_EVENT_BAD_INPUT, ctx, NULL);
		return false;
	}

	if (sin->sin_family != AF_INET) {
		cb(EVTSOCK_EVENT_BAD_INPUT, ctx, NULL);
		return false;
	}

	socks4_req_hdr_t hdr = {
		SOCKS4_REQ_VERSION,
		cmd, htons(sin->sin_port), htonl(sin->sin_addr.s_addr),
		0
	};

	struct evbuffer *evb = evbuffer_new();
	evbuffer_add(evb, &hdr, sizeof(hdr));
	bufferevent_write_buffer(bev, evb);
	evbuffer_free(evb);

	return create_request(bev, socks4_connect_read, cb, ctx);
}