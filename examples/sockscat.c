#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include <evtssl.h>

#include "evtsock.h"

typedef struct {
	const char *dst_host;
	unsigned long dst_port;
	const char *proxy_host;
	unsigned long proxy_port;
	const char *cafile;
	const char *cadir;
	const char *key;
	const char *cert;
	bool nossl;
	int family;
} sc_opts_t;

typedef struct {
	struct event_base *base;
	struct event *sig_event;

	struct event *evt_out;
	struct event *evt_in;

	evt_ssl_t *essl;
	evtsock_t *esock;

	struct bufferevent *bev;

	sc_opts_t so;
} sockscat_t;

#define wnjb(a) (a & ~(EAGAIN | EWOULDBLOCK))

static void stdout_cb(evutil_socket_t fd, short events, void *ctx)
{
	sockscat_t *sc = ctx;

	ssize_t rlen;
	uint8_t buf[512];
	if (events & EV_READ) {
		rlen = read(fd, buf, sizeof(buf));
		if (rlen == 0) {
			fprintf(stderr, "stdout was closed\n");
			goto ouch_fd;
		}
		else if ((rlen == -1) && wnjb(errno)) {
			fprintf(stderr, "stdout ouched (%zd,%d): %s\n", rlen, errno, strerror(errno));
			goto ouch_fd;
		}
	}

	ssize_t wlen;
	struct evbuffer *evb = bufferevent_get_input(sc->bev);
	while ((rlen = evbuffer_copyout(evb, buf, sizeof(buf))) > 0) {
		wlen = write(fd, buf, rlen);
		if (wlen == -1) {
			if (!wnjb(errno)) {
				break;
			}
			else {
				fprintf(stderr, "stdout had an accident: %s\n", strerror(errno));
				goto ouch;
			}
		}
		evbuffer_drain(evb, wlen);
	}

	if (evbuffer_get_length(evb) > 0)
		event_add(sc->evt_out, NULL);

	return;
ouch_fd:
	close(fd);

ouch:
	event_free(sc->evt_out);
	sc->evt_out = NULL;

	if (!sc->evt_in)
		event_base_loopbreak(sc->base);
}

static void stdin_cb(evutil_socket_t fd, short events, void *ctx)
{
	(void) events;

	sockscat_t *sc = ctx;

	char buf[512];
	ssize_t len;
	while ((len = read(fd, buf, sizeof(buf))) > 0) {
		bufferevent_write(sc->bev, buf, len);
	}

	if (len == 0) {
		fprintf(stderr, "stdin was closed\n");
		close(STDIN_FILENO);
		goto ouch;
	}
	else if ((len == -1) && wnjb(errno)) {
		fprintf(stderr, "stdin had an accident: %s\n", strerror(errno));
		goto ouch;
	}

	return;
ouch:
	event_free(sc->evt_in);
	sc->evt_in = NULL;

	if (!sc->evt_out)
		event_base_loopbreak(sc->base);
}

static void beveventcb(struct bufferevent *bev, short events, void *ctx)
{
	(void) bev;

	sockscat_t *sc = ctx;

	if (events & BEV_EVENT_CONNECTED) {
		return;
	}
	else if (events & BEV_EVENT_ERROR) {
		fprintf(stderr, "connection had an accident: %s\n", strerror(errno));
	}
	else if (events & BEV_EVENT_TIMEOUT) {
		fprintf(stderr, "connection timed out\n");
	}
	else if (events & BEV_EVENT_EOF) {
		fprintf(stderr, "connection was closed: %d\n", events);
	}

	event_base_loopbreak(sc->base);
}

static void bevreadcb(struct bufferevent *bev, void *ctx)
{
	(void) bev;

	sockscat_t *sc = ctx;

	if (sc->evt_out) {
		event_add(sc->evt_out, NULL);
	}
	else{
		fprintf(stderr, "stdout closed\n");
		event_base_loopbreak(sc->base);
	}
}

static void handle_interrupt(int fd, short events, void *arg)
{
	(void) fd;
	(void) events;

	sockscat_t *sc = arg;

	event_base_loopbreak(sc->base);
}

static struct event_base *get_fd_rdy_event_base(void)
{
  struct event_config *evcfg = event_config_new();
  event_config_require_features(evcfg, EV_FEATURE_FDS);
  struct event_base *base = event_base_new_with_config(evcfg);
  event_config_free(evcfg);
  return base;
}

static void ssl_error_cb(evt_ssl_t *essl, evt_ssl_error_t error)
{
	sockscat_t *sc = evt_ssl_get_ctx(essl);

	fprintf(stderr, "ssl error(%d): %s\n", error, evt_ssl_get_error_str(essl));

	event_base_loopbreak(sc->base);
}

static struct bufferevent *get_new_sock_bev(void *arg)
{
	sockscat_t *sc = arg;
	return evt_ssl_connect(sc->essl);
}

static void socks_cb(evtsock_event_t evt, void *ctx, evtsock_res_t *res)
{
	sockscat_t *sc = ctx;

	if (evt != EVTSOCK_EVENT_SUCCESS) {
		fprintf(stderr, "socks ouch: %d - %s\n", evt, strerror(errno));
		event_base_loopbreak(sc->base);
		return;
	}

	sc->bev = res->bev;
	bufferevent_setcb(res->bev, bevreadcb, NULL, beveventcb, sc);
	bufferevent_enable(res->bev, EV_READ | EV_WRITE);
	event_add(sc->evt_in, NULL);
}

enum option_repr {
	opt_dst_host = 1,
	opt_dst_port,
	opt_proxy_host,
	opt_proxy_port,
	opt_cafile,
	opt_cadir,
	opt_key,
	opt_cert,
	opt_nossl,
	opt_family,
	opt_reconnect,
};
static struct option options[] = {
	{ "dst-host", 1, NULL, opt_dst_host },
	{ "dst-port", 1, NULL, opt_dst_port },
	{ "proxy-host", 1, NULL, opt_proxy_host },
	{ "proxy-port", 1, NULL, opt_proxy_port },
	{ "cafile", 1, NULL, opt_cafile },
	{ "cadir", 1, NULL, opt_cadir },
	{ "key", 1, NULL, opt_key },
	{ "cert", 1, NULL, opt_cert },
	{ "nossl", 0, NULL, opt_nossl },
	{ "family", 1, NULL, opt_family },
	{ NULL, 0, NULL, 0 }
};

static void print_help(void)
{
	struct option *opt = &options[0];
	while (opt->name) {
		fputs("--", stdout);
		fputs(opt->name, stdout);
		if (opt->has_arg > 0) {
			fputs(" ", stdout);
			if (opt->has_arg > 1)
				fputs("[", stdout);
			fputs("arg", stdout);
			if (opt->has_arg > 1)
				fputs("]", stdout);
		}
		puts("");
		opt++;
	}
	puts("family can be either 4 or 6 (unspec elsewise)");
}

// TODO option, arg, param... naming?

static bool parse_args(sc_opts_t *so, int argc, char *argv[])
{
	int c;
	memset(so, 0, sizeof(sc_opts_t));

	while ((c = getopt_long(argc, argv, "", options, NULL)) != -1) {
		if ((c == '?') || (c == ':')) {
			fprintf(stderr, "getopt failed (%c)\n", c);
			break;
		}

		switch (c) {
		case opt_dst_host:
			so->dst_host = optarg;
			break;
		case opt_dst_port:
			errno = 0;
			so->dst_port = strtoul(optarg, NULL, 0);
			if (errno != 0) {
				fprintf(stderr, "can't convert port: %s\n", strerror(errno));
				return false;
			}
			break;
		case opt_proxy_host:
			so->proxy_host = optarg;
			break;
		case opt_proxy_port:
			errno = 0;
			so->proxy_port = strtoul(optarg, NULL, 0);
			if (errno != 0) {
				fprintf(stderr, "can't convert port: %s\n", strerror(errno));
				return false;
			}
			break;
		case opt_cafile:
			so->cafile = optarg;
			break;
		case opt_cadir:
			so->cadir = optarg;
			break;
		case opt_key:
			so->key = optarg;
			break;
		case opt_cert:
			so->cert = optarg;
			break;
		case opt_nossl:
			so->nossl = true;
			break;
		case opt_family:
			if (strcmp(optarg, "4") == 0)
				so->family = AF_INET;
			else if (strcmp(optarg, "6") == 0)
				so->family = AF_INET6;
			break;
		default:
			fprintf(stderr, "getopt_long huh? (%d)\n", c);
			break;
		}
	}

	return true;
}

static const char *config_ssl(evt_ssl_t *essl, SSL_CTX *ssl_ctx, void *ctx)
{
	(void) ctx;

	sockscat_t *sc = evt_ssl_get_ctx(essl);

	if (sc->so.cafile || sc->so.cadir) {
		if (SSL_CTX_load_verify_locations(ssl_ctx, sc->so.cafile, sc->so.cadir) < 1) {
			return "ca-error!";
		}
	}

	if (sc->so.cert) {
		if (SSL_CTX_use_certificate_file(ssl_ctx, sc->so.cert, SSL_FILETYPE_PEM) < 1) {
			return "couldn't set certificate!";
		}
	}

	if (sc->so.key) {
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, sc->so.key, SSL_FILETYPE_PEM) < 1) {
			return "couldn't set private key!";
		}

		if (SSL_CTX_check_private_key(ssl_ctx) < 1) {
		  return "invalid private key!";
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		print_help();
		return EXIT_SUCCESS;
	}

	sockscat_t sc;

	if (!parse_args(&sc.so, argc, argv)) {
		fprintf(stderr, "couldn't parse args\n");
		return EXIT_FAILURE;
	}

	int res = EXIT_SUCCESS;

	sc.base = get_fd_rdy_event_base();
	if (!sc.base) {
		fprintf(stderr, "no evbase.. aborting\n");
		return EXIT_FAILURE;
	}

	sc.essl = evt_ssl_create(
		sc.base,
		sc.so.proxy_host,
		sc.so.proxy_port,
		&sc,
		ssl_error_cb
	);

	if (!sc.essl) {
		fprintf(stderr, "failed to init essl\n");
		res = EXIT_FAILURE;
		goto base_cleanup;
	}

	if (!evt_ssl_reconfigure(sc.essl, config_ssl, NULL)) {
		fprintf(stderr, "reconfigure failed: %s\n", evt_ssl_get_error_str(sc.essl));
		res = EXIT_FAILURE;
		goto cleanup_essl;
	}


	if (sc.so.nossl)
		evt_ssl_dont_really_ssl(sc.essl);

	evutil_make_socket_nonblocking(STDIN_FILENO);
	sc.evt_in = event_new(sc.base, STDIN_FILENO, EV_READ | EV_PERSIST, stdin_cb, &sc);

	evutil_make_socket_nonblocking(STDOUT_FILENO);
	// EV_READ to receive close-events
	sc.evt_out = event_new(sc.base, STDOUT_FILENO, EV_READ | EV_WRITE | EV_PERSIST, stdout_cb, &sc);

	if (sc.so.family != 0)
		evt_ssl_set_family(sc.essl, sc.so.family);


	sc.esock = evtsock_new(get_new_sock_bev, &sc);
	if (!sc.esock) {
		fprintf(stderr, "evtsock_new ouch\n");
		goto past_loop;
	}

	sc.bev = NULL;
	evtsock4_connect_hostname(sc.esock, sc.so.dst_host, sc.so.dst_port, EVTSOCK_CMD_CONNECT_TCP, socks_cb, &sc);

	sc.sig_event = evsignal_new(sc.base, SIGINT, handle_interrupt, &sc);

	event_add(sc.sig_event, NULL);
	event_base_dispatch(sc.base);
	event_free(sc.sig_event);

	evtsock_free(sc.esock);

	if (sc.bev)
		bufferevent_free(sc.bev);

past_loop:
	if (sc.evt_out)
		event_free(sc.evt_out);
	if (sc.evt_in)
		event_free(sc.evt_in);

cleanup_essl:
	evt_ssl_free(sc.essl);

base_cleanup:
	event_base_free(sc.base);

	return res;
}
