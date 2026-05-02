/*
 * libslirp based virtual network interface for LKL
 *
 * Provides user-mode networking without requiring root privileges.
 * Supports port forwarding from host to LKL guest network.
 *
 * Copyright (c) 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <slirp/libslirp.h>

#include "virtio.h"
#include <lkl_host.h>

/* Packet ring buffer between slirp's send_packet callback and LKL's rx */
#define PKT_RING_SIZE 256
#define PKT_MAX_SIZE  65536

struct pkt_entry {
	uint8_t *data;
	int len;
};

struct lkl_netdev_slirp {
	struct lkl_netdev dev;
	Slirp *slirp;
	pthread_t poll_thread;
	int running;

	/* Packet ring: slirp send_packet → LKL rx */
	struct pkt_entry rx_ring[PKT_RING_SIZE];
	int rx_head; /* written by slirp thread (send_packet) */
	int rx_tail; /* read by LKL rx */
	pthread_mutex_t rx_lock;

	/* Wake up the LKL poll when rx packet arrives or shutdown */
	int pipe[2]; /* pipe[0] for poll read, pipe[1] for wakeup write */

	/* Track whether TX is always ready (slirp_input never blocks) */
	int poll_rx;
};

/* ---- slirp callbacks ---- */

static slirp_ssize_t slirp_send_packet_cb(const void *buf, size_t len, void *opaque)
{
	struct lkl_netdev_slirp *nd = opaque;

	pthread_mutex_lock(&nd->rx_lock);
	int next = (nd->rx_head + 1) % PKT_RING_SIZE;
	if (next == nd->rx_tail) {
		/* Ring full, drop packet */
		pthread_mutex_unlock(&nd->rx_lock);
		return (slirp_ssize_t)len; /* pretend success */
	}

	nd->rx_ring[nd->rx_head].data = malloc(len);
	if (!nd->rx_ring[nd->rx_head].data) {
		pthread_mutex_unlock(&nd->rx_lock);
		return -1;
	}
	memcpy(nd->rx_ring[nd->rx_head].data, buf, len);
	nd->rx_ring[nd->rx_head].len = (int)len;
	nd->rx_head = next;
	pthread_mutex_unlock(&nd->rx_lock);

	/* Wake up LKL poll */
	char c = 'r';
	if (write(nd->pipe[1], &c, 1) < 0) {
		/* ignore */
	}

	return (slirp_ssize_t)len;
}

static void slirp_guest_error_cb(const char *msg, void *opaque)
{
	(void)opaque;
	fprintf(stderr, "slirp guest error: %s\n", msg);
}

static int64_t slirp_clock_get_ns_cb(void *opaque)
{
	(void)opaque;
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

struct slirp_timer {
	SlirpTimerCb cb;
	void *cb_opaque;
	int64_t expire_ms; /* -1 = inactive */
};

static void *slirp_timer_new_cb(SlirpTimerCb cb, void *cb_opaque, void *opaque)
{
	(void)opaque;
	struct slirp_timer *t = calloc(1, sizeof(*t));
	if (t) {
		t->cb = cb;
		t->cb_opaque = cb_opaque;
		t->expire_ms = -1;
	}
	return t;
}

static void slirp_timer_free_cb(void *timer, void *opaque)
{
	(void)opaque;
	free(timer);
}

static void slirp_timer_mod_cb(void *timer, int64_t expire_time, void *opaque)
{
	(void)opaque;
	struct slirp_timer *t = timer;
	t->expire_ms = expire_time;
}

static void slirp_register_poll_fd_cb(int fd, void *opaque)
{
	(void)fd;
	(void)opaque;
}

static void slirp_unregister_poll_fd_cb(int fd, void *opaque)
{
	(void)fd;
	(void)opaque;
}

static void slirp_notify_cb(void *opaque)
{
	struct lkl_netdev_slirp *nd = opaque;
	char c = 'n';
	if (write(nd->pipe[1], &c, 1) < 0) {
		/* ignore */
	}
}

static SlirpCb slirp_callbacks = {
	.send_packet = slirp_send_packet_cb,
	.guest_error = slirp_guest_error_cb,
	.clock_get_ns = slirp_clock_get_ns_cb,
	.timer_new = slirp_timer_new_cb,
	.timer_free = slirp_timer_free_cb,
	.timer_mod = slirp_timer_mod_cb,
	.register_poll_fd = slirp_register_poll_fd_cb,
	.unregister_poll_fd = slirp_unregister_poll_fd_cb,
	.notify = slirp_notify_cb,
};

/* ---- slirp poll thread ---- */

struct poll_state {
	struct pollfd *fds;
	int nfds;
	int capacity;
};

static int add_poll_cb(int fd, int events, void *opaque)
{
	struct poll_state *ps = opaque;

	if (ps->nfds >= ps->capacity) {
		ps->capacity = ps->capacity ? ps->capacity * 2 : 16;
		ps->fds = realloc(ps->fds, sizeof(struct pollfd) * ps->capacity);
	}

	int idx = ps->nfds++;
	ps->fds[idx].fd = fd;
	ps->fds[idx].events = 0;
	ps->fds[idx].revents = 0;
	if (events & SLIRP_POLL_IN)
		ps->fds[idx].events |= POLLIN;
	if (events & SLIRP_POLL_OUT)
		ps->fds[idx].events |= POLLOUT;
	if (events & SLIRP_POLL_PRI)
		ps->fds[idx].events |= POLLPRI;
	return idx;
}

static int get_revents_cb(int idx, void *opaque)
{
	struct poll_state *ps = opaque;
	int revents = 0;

	if (idx < 0 || idx >= ps->nfds)
		return 0;

	if (ps->fds[idx].revents & POLLIN)
		revents |= SLIRP_POLL_IN;
	if (ps->fds[idx].revents & POLLOUT)
		revents |= SLIRP_POLL_OUT;
	if (ps->fds[idx].revents & POLLPRI)
		revents |= SLIRP_POLL_PRI;
	if (ps->fds[idx].revents & POLLERR)
		revents |= SLIRP_POLL_ERR;
	if (ps->fds[idx].revents & POLLHUP)
		revents |= SLIRP_POLL_HUP;
	return revents;
}

static void *slirp_poll_thread_fn(void *arg)
{
	struct lkl_netdev_slirp *nd = arg;
	struct poll_state ps = {0};

	while (nd->running) {
		uint32_t timeout = 100; /* ms */
		ps.nfds = 0;

		slirp_pollfds_fill(nd->slirp, &timeout, add_poll_cb, &ps);

		int ret = poll(ps.fds, ps.nfds, (int)timeout);
		if (ret < 0 && errno == EINTR)
			continue;

		slirp_pollfds_poll(nd->slirp, ret < 0 ? 1 : 0,
				   get_revents_cb, &ps);
	}

	free(ps.fds);
	return NULL;
}

/* ---- LKL netdev ops ---- */

static int slirp_net_tx(struct lkl_netdev *dev, struct iovec *iov, int cnt)
{
	struct lkl_netdev_slirp *nd =
		container_of(dev, struct lkl_netdev_slirp, dev);

	/* Gather iov into contiguous buffer for slirp_input */
	int total = 0;
	for (int i = 0; i < cnt; i++)
		total += iov[i].iov_len;

	uint8_t *buf = malloc(total);
	if (!buf)
		return -1;

	int off = 0;
	for (int i = 0; i < cnt; i++) {
		memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
		off += iov[i].iov_len;
	}

	slirp_input(nd->slirp, buf, total);
	free(buf);
	return total;
}

static int slirp_net_rx(struct lkl_netdev *dev, struct iovec *iov, int cnt)
{
	struct lkl_netdev_slirp *nd =
		container_of(dev, struct lkl_netdev_slirp, dev);

	pthread_mutex_lock(&nd->rx_lock);
	if (nd->rx_tail == nd->rx_head) {
		/* No packet available */
		pthread_mutex_unlock(&nd->rx_lock);
		nd->poll_rx = 1;
		return -1;
	}

	struct pkt_entry *pkt = &nd->rx_ring[nd->rx_tail];
	int pkt_len = pkt->len;

	/* Scatter into iov */
	int off = 0;
	for (int i = 0; i < cnt && off < pkt_len; i++) {
		int to_copy = pkt_len - off;
		if (to_copy > (int)iov[i].iov_len)
			to_copy = (int)iov[i].iov_len;
		memcpy(iov[i].iov_base, pkt->data + off, to_copy);
		off += to_copy;
	}

	free(pkt->data);
	pkt->data = NULL;
	pkt->len = 0;
	nd->rx_tail = (nd->rx_tail + 1) % PKT_RING_SIZE;
	pthread_mutex_unlock(&nd->rx_lock);

	return off;
}

static int slirp_net_poll(struct lkl_netdev *dev)
{
	struct lkl_netdev_slirp *nd =
		container_of(dev, struct lkl_netdev_slirp, dev);

	struct pollfd pfd = {
		.fd = nd->pipe[0],
		.events = POLLIN,
	};

	int ret;
	do {
		ret = poll(&pfd, 1, -1);
	} while (ret == -1 && errno == EINTR);

	if (ret < 0)
		return -1;

	if (pfd.revents & (POLLHUP | POLLNVAL))
		return LKL_DEV_NET_POLL_HUP;

	if (pfd.revents & POLLIN) {
		char tmp[256];
		read(nd->pipe[0], tmp, sizeof(tmp));
	}

	int result = LKL_DEV_NET_POLL_TX; /* slirp_input never blocks */

	pthread_mutex_lock(&nd->rx_lock);
	if (nd->rx_tail != nd->rx_head) {
		nd->poll_rx = 0;
		result |= LKL_DEV_NET_POLL_RX;
	}
	pthread_mutex_unlock(&nd->rx_lock);

	return result;
}

static void slirp_net_poll_hup(struct lkl_netdev *dev)
{
	struct lkl_netdev_slirp *nd =
		container_of(dev, struct lkl_netdev_slirp, dev);

	nd->running = 0;
	close(nd->pipe[0]);
	close(nd->pipe[1]);
}

static void slirp_net_free(struct lkl_netdev *dev)
{
	struct lkl_netdev_slirp *nd =
		container_of(dev, struct lkl_netdev_slirp, dev);

	nd->running = 0;
	pthread_join(nd->poll_thread, NULL);
	slirp_cleanup(nd->slirp);

	/* Free any remaining packets in ring */
	while (nd->rx_tail != nd->rx_head) {
		free(nd->rx_ring[nd->rx_tail].data);
		nd->rx_tail = (nd->rx_tail + 1) % PKT_RING_SIZE;
	}

	pthread_mutex_destroy(&nd->rx_lock);
	free(nd);
}

static struct lkl_dev_net_ops slirp_net_ops = {
	.tx = slirp_net_tx,
	.rx = slirp_net_rx,
	.poll = slirp_net_poll,
	.poll_hup = slirp_net_poll_hup,
	.free = slirp_net_free,
};

/* ---- Public API ---- */

/**
 * lkl_netdev_slirp_create - create a slirp-based network device
 *
 * Creates a user-mode networking stack. The guest gets IP 10.0.2.15/24
 * with gateway/host at 10.0.2.2 and DNS at 10.0.2.3 by default.
 * No root privileges required.
 *
 * Returns: pointer to lkl_netdev on success, NULL on failure
 */
struct lkl_netdev *lkl_netdev_slirp_create(void)
{
	struct lkl_netdev_slirp *nd = calloc(1, sizeof(*nd));
	if (!nd)
		return NULL;

	pthread_mutex_init(&nd->rx_lock, NULL);

	if (pipe(nd->pipe) < 0) {
		perror("slirp: pipe");
		free(nd);
		return NULL;
	}
	fcntl(nd->pipe[0], F_SETFL, O_NONBLOCK);

	/* Configure slirp */
	SlirpConfig cfg = {
		.version = 4,
		.in_enabled = true,
		.vnetwork = { .s_addr = inet_addr("10.0.2.0") },
		.vnetmask = { .s_addr = inet_addr("255.255.255.0") },
		.vhost = { .s_addr = inet_addr("10.0.2.2") },
		.in6_enabled = false,
		.vhostname = "lkl-host",
		.vdhcp_start = { .s_addr = inet_addr("10.0.2.15") },
		.vnameserver = { .s_addr = inet_addr("10.0.2.3") },
		.disable_host_loopback = false,
	};

	nd->slirp = slirp_new(&cfg, &slirp_callbacks, nd);
	if (!nd->slirp) {
		fprintf(stderr, "slirp: failed to create instance\n");
		close(nd->pipe[0]);
		close(nd->pipe[1]);
		pthread_mutex_destroy(&nd->rx_lock);
		free(nd);
		return NULL;
	}

	/* Start slirp poll thread */
	nd->running = 1;
	if (pthread_create(&nd->poll_thread, NULL, slirp_poll_thread_fn, nd) != 0) {
		fprintf(stderr, "slirp: failed to create poll thread\n");
		slirp_cleanup(nd->slirp);
		close(nd->pipe[0]);
		close(nd->pipe[1]);
		pthread_mutex_destroy(&nd->rx_lock);
		free(nd);
		return NULL;
	}

	nd->dev.ops = &slirp_net_ops;
	return &nd->dev;
}

/**
 * lkl_netdev_slirp_add_hostfwd - add port forwarding from host to guest
 *
 * Forward connections to host_addr:host_port to guest_addr:guest_port.
 * Must be called after lkl_netdev_slirp_create().
 *
 * @nd - the netdev returned by lkl_netdev_slirp_create()
 * @is_udp - 1 for UDP, 0 for TCP
 * @host_addr - host address to listen on (e.g. "0.0.0.0" for all)
 * @host_port - host port number
 * @guest_addr - guest address (e.g. "10.0.2.15")
 * @guest_port - guest port number
 *
 * Returns: 0 on success, -1 on failure
 */
int lkl_netdev_slirp_add_hostfwd(struct lkl_netdev *nd, int is_udp,
				  const char *host_addr, int host_port,
				  const char *guest_addr, int guest_port)
{
	struct lkl_netdev_slirp *nds =
		container_of(nd, struct lkl_netdev_slirp, dev);

	struct in_addr haddr, gaddr;
	inet_aton(host_addr, &haddr);
	inet_aton(guest_addr, &gaddr);

	return slirp_add_hostfwd(nds->slirp, is_udp, haddr, host_port,
				 gaddr, guest_port);
}

/**
 * lkl_netdev_slirp_remove_hostfwd - remove a port forwarding rule
 *
 * @nd - the netdev returned by lkl_netdev_slirp_create()
 * @is_udp - 1 for UDP, 0 for TCP
 * @host_addr - host address
 * @host_port - host port number
 *
 * Returns: 0 on success, -1 on failure
 */
int lkl_netdev_slirp_remove_hostfwd(struct lkl_netdev *nd, int is_udp,
				     const char *host_addr, int host_port)
{
	struct lkl_netdev_slirp *nds =
		container_of(nd, struct lkl_netdev_slirp, dev);

	struct in_addr haddr;
	inet_aton(host_addr, &haddr);

	return slirp_remove_hostfwd(nds->slirp, is_udp, haddr, host_port);
}
