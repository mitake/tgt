/*
 * Software iSCSI target over TCP/IP Data-Path
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/eventfd.h>

#include "iscsid.h"
#include "tgtd.h"
#include "util.h"
#include "work.h"

int nr_tcp_iothreads = 1;

static void iscsi_tcp_st_event_handler(int fd, int events, void *data);
static void iscsi_tcp_mt_event_handler(int fd, int events, void *data);
static void iscsi_tcp_release(struct iscsi_connection *conn);
static struct iscsi_task *iscsi_tcp_alloc_task(struct iscsi_connection *conn,
						size_t ext_len);
static void iscsi_tcp_free_task(struct iscsi_task *task);

static long nop_ttt;

static int listen_fds[8];
static struct iscsi_transport iscsi_tcp;

enum iscsi_tcp_work_state {
	ISCSI_TCP_WORK_INIT,
	ISCSI_TCP_WORK_RX,
	ISCSI_TCP_WORK_RX_BHS,
	ISCSI_TCP_WORK_RX_EAGAIN,
	ISCSI_TCP_WORK_RX_FAILED,
	ISCSI_TCP_WORK_TX,
	ISCSI_TCP_WORK_TX_FAILED,
};

struct iscsi_tcp_work {
	/* list: connected to iscsi_tcp_work_list or iscsi_tcp_finished_list */
	struct list_head list;

	enum iscsi_tcp_work_state state;
};

struct iscsi_tcp_per_thread_queue {
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	struct list_head work_list;
};

struct iscsi_tcp_connection {
	int fd;

	struct list_head tcp_conn_siblings;
	int nop_inflight_count;
	int nop_interval;
	int nop_tick;
	int nop_count;
	long ttt;

	struct iscsi_connection iscsi_conn;

	int used_in_worker_thread;
	int restore_events;

	struct iscsi_tcp_work work;
	int worker_done_fd;
	struct iscsi_tcp_per_thread_queue *queue;
};

static pthread_mutex_t iscsi_tcp_worker_startup_mutex =
	PTHREAD_MUTEX_INITIALIZER;

static int iscsi_tcp_worker_stop;

static pthread_t *iscsi_tcp_worker_threads;
static struct iscsi_tcp_per_thread_queue *iscsi_tcp_per_thread_queues;

static void queue_iscsi_tcp_work(struct iscsi_connection *conn, int events);

static void iscsi_tcp_work_done_handler(int fd, int events, void *data)
{
	struct iscsi_tcp_work *work;
	struct iscsi_connection *conn;
	struct iscsi_tcp_connection *tcp_conn = data;
	int ret, failed;
	eventfd_t dummy;

	ret = eventfd_read(fd, &dummy);
	if (ret < 0) {
		eprintf("iscsi tcp work error: %m\n");
		exit(1);
	}

	work = &tcp_conn->work;
	conn = &tcp_conn->iscsi_conn;

	tcp_conn->used_in_worker_thread = 0;

	ret = tgt_event_add(tcp_conn->fd, tcp_conn->restore_events,
			    iscsi_tcp_mt_event_handler, conn);
	if (ret < 0) {
		/* fd is broken by worker threads */
		failed = 1;
		goto end;
	}

	failed = 0;

	if (conn->state == STATE_CLOSE)
		goto end;

	switch (work->state) {
	case ISCSI_TCP_WORK_RX_FAILED:
	case ISCSI_TCP_WORK_TX_FAILED:
		failed = 1;
		goto end;
	case ISCSI_TCP_WORK_RX:
		if (is_conn_rx_end(conn))
			iscsi_rx_done(conn);
		break;
	case ISCSI_TCP_WORK_RX_BHS:
		if (is_conn_rx_bhs(conn))
			/* EAGAIN or EINTR */
			break;

		iscsi_pre_iostate_rx_init_ahs(conn);
		if (conn->state == STATE_CLOSE)
			break;

		/* bypass the main event loop */
		work->state = ISCSI_TCP_WORK_RX;
		queue_iscsi_tcp_work(conn, tcp_conn->restore_events);
		return;
	case ISCSI_TCP_WORK_TX:
		if (is_conn_tx_end(conn))
			iscsi_tx_done(conn);
		break;
	default:
		eprintf("invalid state of iscsi work tcp: %d\n",
			work->state);
		exit(1);
	}

	tcp_conn->restore_events = 0;

end:
	work->state = ISCSI_TCP_WORK_INIT;
	if (failed || conn->state == STATE_CLOSE) {
		dprintf("connection closed %p\n", conn);
		conn_close(conn);
	}
}

static void *iscsi_tcp_worker_fn(void *arg)
{
	sigset_t set;
	struct iscsi_tcp_work *work;
	struct iscsi_connection *conn;
	struct iscsi_tcp_connection *tcp_conn;
	int ret;
	struct iscsi_tcp_per_thread_queue *queue = arg;

	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, NULL);

	pthread_mutex_lock(&iscsi_tcp_worker_startup_mutex);
	pthread_mutex_unlock(&iscsi_tcp_worker_startup_mutex);

	dprintf("starting iscsi tcp worker thread: %lu\n", pthread_self());

	while (!iscsi_tcp_worker_stop) {
		pthread_mutex_lock(&queue->mutex);
retest:
		if (list_empty(&queue->work_list)) {
			pthread_cond_wait(&queue->cond, &queue->mutex);

			if (iscsi_tcp_worker_stop) {
				pthread_mutex_unlock(&queue->mutex);
				pthread_exit(NULL);
			}

			goto retest;
		}

		work = list_first_entry(&queue->work_list,
				       struct iscsi_tcp_work, list);

		list_del(&work->list);
		pthread_mutex_unlock(&queue->mutex);

		tcp_conn =
			container_of(work, struct iscsi_tcp_connection, work);
		conn = &tcp_conn->iscsi_conn;

		switch (work->state) {
		case ISCSI_TCP_WORK_RX_BHS:
			ret = iscsi_rx_bhs_handler(conn);
			if (ret < 0)
				work->state = ISCSI_TCP_WORK_RX_FAILED;
			break;
		case ISCSI_TCP_WORK_RX:
			do {
				ret = iscsi_rx_handler(conn);
				if (ret == -EAGAIN)
					break;
				if (ret == -EINTR)
					continue;

				if (ret < 0) {
					work->state = ISCSI_TCP_WORK_RX_FAILED;
					break;
				}
			} while (conn->state != STATE_CLOSE &&
				 !is_conn_rx_end(conn));
			break;
		case ISCSI_TCP_WORK_TX:
			do {
				ret = iscsi_tx_handler(conn);
				if (ret < 0) {
					work->state = ISCSI_TCP_WORK_TX_FAILED;
					break;
				}
			} while (conn->state != STATE_CLOSE &&
				 !is_conn_tx_end(conn));
			break;
		default:
			eprintf("invalid state of iscsi tcp work: %d\n",
				work->state);
			exit(1);
		}

		ret = eventfd_write(tcp_conn->worker_done_fd, 1);
		if (ret < 0) {
			eprintf("iscsi tcp work error: %m\n");
			exit(1);
		}
	}

	pthread_exit(NULL);
}

static inline struct iscsi_tcp_connection *TCP_CONN(struct iscsi_connection *conn)
{
	return container_of(conn, struct iscsi_tcp_connection, iscsi_conn);
}

static void queue_iscsi_tcp_work(struct iscsi_connection *conn, int events)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);
	struct iscsi_tcp_work *work = &tcp_conn->work;
	struct iscsi_tcp_per_thread_queue *queue = tcp_conn->queue;

	tcp_conn->used_in_worker_thread = 1;

	tcp_conn->restore_events = events;

	tgt_event_del(tcp_conn->fd);

	pthread_mutex_lock(&queue->mutex);
	list_add_tail(&work->list, &queue->work_list);
	pthread_mutex_unlock(&queue->mutex);

	pthread_cond_signal(&queue->cond);
}

static struct tgt_work nop_work;

/* all iscsi connections */
static struct list_head iscsi_tcp_conn_list;

static int iscsi_send_ping_nop_in(struct iscsi_tcp_connection *tcp_conn)
{
	struct iscsi_connection *conn = &tcp_conn->iscsi_conn;
	struct iscsi_task *task = NULL;

	task = iscsi_tcp_alloc_task(&tcp_conn->iscsi_conn, 0);
	task->conn = conn;

	task->tag = ISCSI_RESERVED_TAG;
	task->req.opcode = ISCSI_OP_NOOP_IN;
	task->req.itt = cpu_to_be32(ISCSI_RESERVED_TAG);
	task->req.ttt = cpu_to_be32(tcp_conn->ttt);

	list_add_tail(&task->c_list, &task->conn->tx_clist);
	task->conn->tp->ep_event_modify(task->conn, EPOLLIN | EPOLLOUT);

	return 0;
}

static void iscsi_tcp_nop_work_handler(void *data)
{
	struct iscsi_tcp_connection *tcp_conn;

	list_for_each_entry(tcp_conn, &iscsi_tcp_conn_list, tcp_conn_siblings) {
		if (tcp_conn->used_in_worker_thread)
			continue;

		if (tcp_conn->nop_interval == 0)
			continue;

		tcp_conn->nop_tick--;
		if (tcp_conn->nop_tick > 0)
			continue;

		tcp_conn->nop_tick = tcp_conn->nop_interval;

		tcp_conn->nop_inflight_count++;
		if (tcp_conn->nop_inflight_count > tcp_conn->nop_count) {
			eprintf("tcp connection timed out after %d failed " \
				"NOP-OUT\n", tcp_conn->nop_count);
			conn_close(&tcp_conn->iscsi_conn);
			/* cant/shouldnt delete tcp_conn from within the loop */
			break;
		}
		nop_ttt++;
		if (nop_ttt == ISCSI_RESERVED_TAG)
			nop_ttt = 1;

		tcp_conn->ttt = nop_ttt;
		iscsi_send_ping_nop_in(tcp_conn);
	}

	add_work(&nop_work, 1);
}

static void iscsi_tcp_nop_reply(long ttt)
{
	struct iscsi_tcp_connection *tcp_conn;

	list_for_each_entry(tcp_conn, &iscsi_tcp_conn_list, tcp_conn_siblings) {
		if (tcp_conn->ttt != ttt)
			continue;
		tcp_conn->nop_inflight_count = 0;
	}
}

int iscsi_update_target_nop_count(int tid, int count)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &iscsi_targets_list, tlist) {
		if (target->tid != tid)
			continue;
		target->nop_count = count;
		return 0;
	}
	return -1;
}

int iscsi_update_target_nop_interval(int tid, int interval)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &iscsi_targets_list, tlist) {
		if (target->tid != tid)
			continue;
		target->nop_interval = interval;
		return 0;
	}
	return -1;
}

void iscsi_set_nop_interval(int interval)
{
	default_nop_interval = interval;
}

void iscsi_set_nop_count(int count)
{
	default_nop_count = count;
}

static int set_keepalive(int fd)
{
	int ret, opt;

	opt = 1;
	ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
	if (ret)
		return ret;

	opt = 1800;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt));
	if (ret)
		return ret;

	opt = 6;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt));
	if (ret)
		return ret;

	opt = 300;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt));
	if (ret)
		return ret;

	return 0;
}

static int set_nodelay(int fd)
{
	int ret, opt;

	opt = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	return ret;
}

static struct iscsi_tcp_per_thread_queue *pick_queue(void)
{
	static int next_idx;
	struct iscsi_tcp_per_thread_queue *ret;

	ret = &iscsi_tcp_per_thread_queues[next_idx++];
	next_idx %= nr_tcp_iothreads;

	return ret;
}

static void accept_connection(int afd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	struct iscsi_connection *conn;
	struct iscsi_tcp_connection *tcp_conn;
	int fd, ret;

	dprintf("%d\n", afd);

	namesize = sizeof(from);
	fd = accept(afd, (struct sockaddr *) &from, &namesize);
	if (fd < 0) {
		eprintf("can't accept, %m\n");
		return;
	}

	if (!is_system_available())
		goto out;

	if (list_empty(&iscsi_targets_list))
		goto out;

	ret = set_keepalive(fd);
	if (ret)
		goto out;

	ret = set_nodelay(fd);
	if (ret)
		goto out;

	tcp_conn = zalloc(sizeof(*tcp_conn));
	if (!tcp_conn)
		goto out;

	INIT_LIST_HEAD(&tcp_conn->work.list);
	tcp_conn->work.state = ISCSI_TCP_WORK_INIT;

	conn = &tcp_conn->iscsi_conn;

	ret = conn_init(conn);
	if (ret)
		goto free_tcp_conn;

	tcp_conn->fd = fd;
	conn->tp = &iscsi_tcp;

	conn_read_pdu(conn);
	set_non_blocking(fd);

	ret = tgt_event_add(fd, EPOLLIN,
			    nr_tcp_iothreads == 1 ?
			    iscsi_tcp_st_event_handler :
			    iscsi_tcp_mt_event_handler,
			    conn);
	if (ret)
		goto conn_exit2;

	if (1 < nr_tcp_iothreads) {
		tcp_conn->worker_done_fd = eventfd(0, O_NONBLOCK);
		if (tcp_conn->worker_done_fd < 0)
			goto del_ev_fd;

		ret = tgt_event_add(tcp_conn->worker_done_fd, EPOLLIN,
				    iscsi_tcp_work_done_handler, tcp_conn);
		if (ret)
			goto close_done_fd;

		tcp_conn->queue = pick_queue();
	}

	list_add(&tcp_conn->tcp_conn_siblings, &iscsi_tcp_conn_list);

	return;

close_done_fd:
	close(tcp_conn->worker_done_fd);
del_ev_fd:
	tgt_event_del(fd);
conn_exit2:
	conn_exit(conn);
free_tcp_conn:
	free(tcp_conn);

out:
	close(fd);
	return;
}

static void iscsi_tcp_st_event_handler(int fd, int events, void *data)
{
	int ret;

	struct iscsi_connection *conn = (struct iscsi_connection *) data;

	if (events & EPOLLIN) {
		if (is_conn_rx_bhs(conn)) {
			ret = iscsi_rx_bhs_handler(conn);
			if (!is_conn_rx_init_ahs(conn)
			    || ret < 0 || conn->state == STATE_CLOSE)
				goto epollin_end;
		}

		if (conn->state != STATE_CLOSE && is_conn_rx_init_ahs(conn)) {
			iscsi_pre_iostate_rx_init_ahs(conn);

			if (conn->state == STATE_CLOSE)
				goto epollin_end;
		}

		if (conn->state != STATE_CLOSE)
			iscsi_rx_handler(conn);

		if (conn->state != STATE_CLOSE && is_conn_rx_end(conn))
			iscsi_rx_done(conn);
	}

epollin_end:
	if (conn->state == STATE_CLOSE)
		dprintf("connection closed\n");

	if (conn->state != STATE_CLOSE && events & EPOLLOUT) {
		if (conn->state == STATE_SCSI && !conn->tx_task) {
			if (iscsi_task_tx_start(conn))
				goto epollout_end;
		}

		if (conn->state != STATE_CLOSE)
			iscsi_tx_handler(conn);

		if (conn->state != STATE_CLOSE && is_conn_tx_end(conn))
			iscsi_tx_done(conn);
	}

epollout_end:
	if (conn->state == STATE_CLOSE) {
		dprintf("connection closed %p\n", conn);
		conn_close(conn);
	}
}

static void iscsi_tcp_mt_event_handler(int fd, int events, void *data)
{
	struct iscsi_connection *conn = (struct iscsi_connection *) data;
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);
	struct iscsi_tcp_work *work = &tcp_conn->work;

	if (work->state != ISCSI_TCP_WORK_INIT) {
		eprintf("invalid state of iscsi tcp work: %d\n", work->state);
		exit(1);
	}

	if (conn->state == STATE_CLOSE) {
		conn_close(conn);
		return;
	}

	if (events & EPOLLIN) {
		if (is_conn_rx_bhs(conn))
			work->state = ISCSI_TCP_WORK_RX_BHS;
		else
			work->state = ISCSI_TCP_WORK_RX;
	} else if (events & EPOLLOUT) {
		if (conn->state == STATE_SCSI && !conn->tx_task) {
			if (iscsi_task_tx_start(conn))
				return;
		}

		work->state = ISCSI_TCP_WORK_TX;
	}

	queue_iscsi_tcp_work(conn, events);
}

int iscsi_tcp_init_portal(char *addr, int port, int tpgt)
{
	struct addrinfo hints, *res, *res0;
	char servname[64];
	int ret, fd, opt, nr_sock = 0;
	struct iscsi_portal *portal = NULL;
	char addrstr[64];
	void *addrptr = NULL;

	port = port ? port : ISCSI_LISTEN_PORT;

	memset(servname, 0, sizeof(servname));
	snprintf(servname, sizeof(servname), "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(addr, servname, &hints, &res0);
	if (ret) {
		eprintf("unable to get address info, %m\n");
		return -errno;
	}

	for (res = res0; res; res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0) {
			if (res->ai_family == AF_INET6)
				dprintf("IPv6 support is disabled.\n");
			else
				eprintf("unable to create fdet %d %d %d, %m\n",
					res->ai_family,	res->ai_socktype,
					res->ai_protocol);
			continue;
		}

		opt = 1;
		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt,
				 sizeof(opt));
		if (ret)
			dprintf("unable to set SO_REUSEADDR, %m\n");

		opt = 1;
		if (res->ai_family == AF_INET6) {
			ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt,
					 sizeof(opt));
			if (ret) {
				close(fd);
				continue;
			}
		}

		ret = bind(fd, res->ai_addr, res->ai_addrlen);
		if (ret) {
			close(fd);
			eprintf("unable to bind server socket, %m\n");
			continue;
		}

		ret = listen(fd, SOMAXCONN);
		if (ret) {
			eprintf("unable to listen to server socket, %m\n");
			close(fd);
			continue;
		}

		set_non_blocking(fd);
		ret = tgt_event_add(fd, EPOLLIN, accept_connection, NULL);
		if (ret)
			close(fd);
		else {
			listen_fds[nr_sock] = fd;
			nr_sock++;
		}

		portal = zalloc(sizeof(struct iscsi_portal));
		switch (res->ai_family) {
		case AF_INET:
			addrptr = &((struct sockaddr_in *)
				    res->ai_addr)->sin_addr;
			break;
		case AF_INET6:
			addrptr = &((struct sockaddr_in6 *)
				    res->ai_addr)->sin6_addr;
			break;
		}
		portal->addr = strdup(inet_ntop(res->ai_family, addrptr,
			     addrstr, sizeof(addrstr)));
		portal->port = port;
		portal->tpgt = tpgt;
		portal->fd   = fd;
		portal->af   = res->ai_family;

		list_add(&portal->iscsi_portal_siblings, &iscsi_portals_list);
	}

	freeaddrinfo(res0);

	return !nr_sock;
}

int iscsi_add_portal(char *addr, int port, int tpgt)
{
	if (iscsi_tcp_init_portal(addr, port, tpgt)) {
		eprintf("failed to create/bind to portal %s:%d\n", addr, port);
		return -1;
	}

	return 0;
};

int iscsi_delete_portal(char *addr, int port)
{
	struct iscsi_portal *portal;

	list_for_each_entry(portal, &iscsi_portals_list,
			    iscsi_portal_siblings) {
		if (!strcmp(addr, portal->addr) && port == portal->port) {
			if (portal->fd != -1)
				tgt_event_del(portal->fd);
			close(portal->fd);
			list_del(&portal->iscsi_portal_siblings);
			free(portal->addr);
			free(portal);
			return 0;
		}
	}
	eprintf("delete_portal failed. No such portal found %s:%d\n",
			addr, port);
	return -1;
}

static int iscsi_tcp_init(void)
{
	int i, ret = 0;

	/* If we were passed any portals on the command line */
	if (portal_arguments)
		iscsi_param_parse_portals(portal_arguments, 1, 0);

	/* if the user did not set a portal we default to wildcard
	   for ipv4 and ipv6
	*/
	if (list_empty(&iscsi_portals_list)) {
		iscsi_add_portal(NULL, 3260, 1);
	}

	INIT_LIST_HEAD(&iscsi_tcp_conn_list);

	nop_work.func = iscsi_tcp_nop_work_handler;
	nop_work.data = &nop_work;
	add_work(&nop_work, 1);

	if (1 < nr_tcp_iothreads) {
		iscsi_tcp_worker_threads = calloc(nr_tcp_iothreads,
						  sizeof(pthread_t));
		if (!iscsi_tcp_worker_threads) {
			eprintf("failed to allocate memory for pthread"\
				" identifier: %m\n");
			ret = -1;

			goto out;
		}

		iscsi_tcp_per_thread_queues = calloc(nr_tcp_iothreads,
				     sizeof(struct iscsi_tcp_per_thread_queue));
		if (!iscsi_tcp_per_thread_queues) {
			eprintf("failed to allocate memory for per thread"\
				"work queue: %m\n");
			ret = -1;
			goto free_worker_threads;
		}

		pthread_mutex_lock(&iscsi_tcp_worker_startup_mutex);
		for (i = 0; i < nr_tcp_iothreads; i++) {
			struct iscsi_tcp_per_thread_queue *queue =
				&iscsi_tcp_per_thread_queues[i];

			pthread_mutex_init(&queue->mutex, NULL);
			pthread_cond_init(&queue->cond, NULL);
			INIT_LIST_HEAD(&queue->work_list);

			ret = pthread_create(&iscsi_tcp_worker_threads[i], NULL,
					     iscsi_tcp_worker_fn, queue);
			if (ret) {
				eprintf("creating worker thread failed: %m\n");
				ret = -1;

				goto terminate_workers;
			}
		}

		pthread_mutex_unlock(&iscsi_tcp_worker_startup_mutex);
		goto out;

terminate_workers:
		iscsi_tcp_worker_stop = 1;
		pthread_mutex_unlock(&iscsi_tcp_worker_startup_mutex);

		for (; 0 <= i; i--)
			pthread_join(iscsi_tcp_worker_threads[i], NULL);

		free(iscsi_tcp_per_thread_queues);

free_worker_threads:
		free(iscsi_tcp_worker_threads);
	}

out:
	return 0;
}

static void iscsi_tcp_exit(void)
{
	int i;
	struct iscsi_portal *portal, *ptmp;

	list_for_each_entry_safe(portal, ptmp, &iscsi_portals_list,
			    iscsi_portal_siblings) {
		iscsi_delete_portal(portal->addr, portal->port);
	}

	iscsi_tcp_worker_stop = 1;
	for (i = 0; i < nr_tcp_iothreads; i++) {
		pthread_cond_signal(&iscsi_tcp_per_thread_queues[i].cond);
		pthread_join(iscsi_tcp_worker_threads[i], NULL);
	}
}

static int iscsi_tcp_conn_login_complete(struct iscsi_connection *conn)
{
	struct iscsi_tcp_connection *tcp_conn;
	struct iscsi_target *target;

	list_for_each_entry(tcp_conn, &iscsi_tcp_conn_list, tcp_conn_siblings)
		if (&tcp_conn->iscsi_conn == conn)
			break;

	if (tcp_conn == NULL)
		return 0;

	list_for_each_entry(target, &iscsi_targets_list, tlist) {
		if (target->tid != conn->tid)
			continue;

		tcp_conn->nop_count = target->nop_count;
		tcp_conn->nop_interval = target->nop_interval;
		tcp_conn->nop_tick = target->nop_interval;
		break;
	}

	return 0;
}

static size_t iscsi_tcp_read(struct iscsi_connection *conn, void *buf,
			     size_t nbytes)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);
	return read(tcp_conn->fd, buf, nbytes);
}

static size_t iscsi_tcp_write_begin(struct iscsi_connection *conn, void *buf,
				    size_t nbytes)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);
	int opt = 1;

	setsockopt(tcp_conn->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
	return write(tcp_conn->fd, buf, nbytes);
}

static void iscsi_tcp_write_end(struct iscsi_connection *conn)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);
	int opt = 0;

	setsockopt(tcp_conn->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
}

static size_t iscsi_tcp_close(struct iscsi_connection *conn)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);

	tgt_event_del(tcp_conn->fd);
	tgt_event_del(tcp_conn->worker_done_fd);

	return 0;
}

static void iscsi_tcp_release(struct iscsi_connection *conn)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);

	conn_exit(conn);
	close(tcp_conn->fd);
	list_del(&tcp_conn->tcp_conn_siblings);
	free(tcp_conn);
}

static int iscsi_tcp_show(struct iscsi_connection *conn, char *buf, int rest)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);
	int err, total = 0;
	socklen_t slen;
	char dst[INET6_ADDRSTRLEN];
	struct sockaddr_storage from;

	slen = sizeof(from);
	err = getpeername(tcp_conn->fd, (struct sockaddr *) &from, &slen);
	if (err < 0) {
		eprintf("%m\n");
		return 0;
	}

	err = getnameinfo((struct sockaddr *)&from, sizeof(from), dst,
			  sizeof(dst), NULL, 0, NI_NUMERICHOST);
	if (err < 0) {
		eprintf("%m\n");
		return 0;
	}

	total = snprintf(buf, rest, "IP Address: %s", dst);

	return total > 0 ? total : 0;
}

static void iscsi_event_modify(struct iscsi_connection *conn, int events)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);
	int ret;

	if (tcp_conn->used_in_worker_thread)
		tcp_conn->restore_events = events;
	else {
		ret = tgt_event_modify(tcp_conn->fd, events);
		if (ret)
			eprintf("tgt_event_modify failed\n");
	}
}

static struct iscsi_task *iscsi_tcp_alloc_task(struct iscsi_connection *conn,
					size_t ext_len)
{
	struct iscsi_task *task;

	task = malloc(sizeof(*task) + ext_len);
	if (task)
		memset(task, 0, sizeof(*task) + ext_len);
	return task;
}

static void iscsi_tcp_free_task(struct iscsi_task *task)
{
	free(task);
}

static void *iscsi_tcp_alloc_data_buf(struct iscsi_connection *conn, size_t sz)
{
	return valloc(sz);
}

static void iscsi_tcp_free_data_buf(struct iscsi_connection *conn, void *buf)
{
	if (buf)
		free(buf);
}

static int iscsi_tcp_getsockname(struct iscsi_connection *conn,
				 struct sockaddr *sa, socklen_t *len)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);

	return getsockname(tcp_conn->fd, sa, len);
}

static int iscsi_tcp_getpeername(struct iscsi_connection *conn,
				 struct sockaddr *sa, socklen_t *len)
{
	struct iscsi_tcp_connection *tcp_conn = TCP_CONN(conn);

	return getpeername(tcp_conn->fd, sa, len);
}

static void iscsi_tcp_conn_force_close(struct iscsi_connection *conn)
{
	conn->state = STATE_CLOSE;
	conn->tp->ep_event_modify(conn, EPOLLIN|EPOLLOUT|EPOLLERR);
}

void iscsi_print_nop_settings(struct concat_buf *b, int tid)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &iscsi_targets_list, tlist) {
		if (target->tid != tid)
			continue;
		if (target->nop_interval == 0)
			continue;

		concat_printf(b,
		      _TAB2 "Nop interval: %d\n"
		      _TAB2 "Nop count: %d\n",
		      target->nop_interval,
		      target->nop_count);
		break;
	}
}

static struct iscsi_transport iscsi_tcp = {
	.name			= "iscsi",
	.rdma			= 0,
	.data_padding		= PAD_WORD_LEN,
	.ep_init		= iscsi_tcp_init,
	.ep_exit		= iscsi_tcp_exit,
	.ep_login_complete	= iscsi_tcp_conn_login_complete,
	.alloc_task		= iscsi_tcp_alloc_task,
	.free_task		= iscsi_tcp_free_task,
	.ep_read		= iscsi_tcp_read,
	.ep_write_begin		= iscsi_tcp_write_begin,
	.ep_write_end		= iscsi_tcp_write_end,
	.ep_close		= iscsi_tcp_close,
	.ep_force_close		= iscsi_tcp_conn_force_close,
	.ep_release		= iscsi_tcp_release,
	.ep_show		= iscsi_tcp_show,
	.ep_event_modify	= iscsi_event_modify,
	.alloc_data_buf		= iscsi_tcp_alloc_data_buf,
	.free_data_buf		= iscsi_tcp_free_data_buf,
	.ep_getsockname		= iscsi_tcp_getsockname,
	.ep_getpeername		= iscsi_tcp_getpeername,
	.ep_nop_reply		= iscsi_tcp_nop_reply,
};

__attribute__((constructor)) static void iscsi_transport_init(void)
{
	iscsi_transport_register(&iscsi_tcp);
}
