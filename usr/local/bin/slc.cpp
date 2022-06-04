// SPDX-License-Identifier: GPL-2.0-only
/*
 * Socket Lost Control.
 *
 * Copyright (C) 2022 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef likely
#define likely(EXPR)	__builtin_expect(!!(EXPR), 1)
#endif

#ifndef unlikely
#define unlikely(EXPR)	__builtin_expect(!!(EXPR), 0)
#endif

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <atomic>
#include <cstdlib>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>

enum {
	PKT_TYPE_SERVER_GET_A_REAL_CLIENT,
	PKT_TYPE_CLIENT_INIT_CIRCUIT,
	PKT_TYPE_CLIENT_START_PRIVATE_SOCK
};

#define PKT_DATA_BUFFER 1024

struct packet {
	uint8_t		type;
	uint8_t		pad;
	uint16_t	len;
	uint8_t		data[PKT_DATA_BUFFER];
};

struct server_data;
struct client_slot {
	int			fd;
	std::atomic<int>	fd_private;
	struct sockaddr_in	addr;
	struct server_data	*data;
};

struct server_data {
	int			fd1;
	int			fd2;
	std::atomic<int>	fd_lost_client;
	std::mutex		map_lock;
	std::unordered_map<uint64_t, struct client_slot *> map;
};

struct client_data {
	int			fd_circuit;
};

static std::atomic<bool> g_stop_app;

static void signal_handler(int sig)
{
	atomic_store(&g_stop_app, true);
	putchar('\n');
	(void)sig;
}

static int create_tcp_sock(void)
{
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		fd = errno;
		perror("socket");
		return -fd;
	}
	return fd;
}

static int setup_reuse(int fd)
{
	int ret, y;
	size_t len = sizeof(y);

	/*
	 * Ignore any error from these calls. They are not mandatory.
	 */
	y = 1;
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&y, len);
	if (unlikely(ret))
		perror("setsockopt(SOL_SOCKET, SO_REUSEADDR)");

	return 0;
}

static int setup_socket(int fd)
{
	int ret, y;
	size_t len = sizeof(y);

	/*
	 * Ignore any error from these calls. They are not mandatory.
	 */
	y = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&y, len);
	if (unlikely(ret < 0))
		perror("setsockopt(IPPROTO_TCP, TCP_NODELAY)");

	y = 1024 * 1024 * 100;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, (void *)&y, len);
	if (unlikely(ret))
		perror("setsockopt(SOL_SOCKET, SO_RCVBUFFORCE)");

	y = 1024 * 1024 * 100;
	ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, (void *)&y, len);
	if (unlikely(ret))
		perror("setsockopt(SOL_SOCKET, SO_SNDBUFFORCE)");

	return 0;
}

static int bind_and_listen_tcp_sock(int fd, const char *baddr, uint16_t bport)
{
	struct sockaddr_in addr;
	int err;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(bport);
	addr.sin_addr.s_addr = inet_addr(baddr);

	setup_socket(fd);
	setup_reuse(fd);
	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		err = errno;
		perror("bind");
		return -err;
	}

	err = listen(fd, 30);
	if (err < 0) {
		err = errno;
		perror("listen");
		return -err;
	}

	return 0;
}

static inline uint64_t gen_map_key(struct sockaddr_in *addr)
{
	return ((uint64_t)addr->sin_addr.s_addr << 16ull) | (uint64_t)addr->sin_port;
}

static int recv_and_send(int fd_in, int fd_out, int *pipes, size_t len)
{
	unsigned int fl = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
	ssize_t read_ret;
	ssize_t write_ret;
	int ret;

	read_ret = splice(fd_in, NULL, pipes[1], NULL, len, fl);
	if (unlikely(read_ret <= 0)) {
		if (read_ret == 0) {
			puts("fd_in is down");
			return -ENETDOWN;
		}
		ret = errno;
		perror("splice fd_in");
		return -ret;
	}

do_write:
	write_ret = splice(pipes[0], NULL, fd_out, NULL, read_ret, fl);
	if (unlikely(write_ret <= 0)) {
		if (write_ret == 0) {
			puts("fd_out is down");
			return -ENETDOWN;
		}
		ret = errno;
		perror("splice fd_out");
		return -ret;
	}

	read_ret -= write_ret;
	if (unlikely(read_ret > 0))
		goto do_write;

	return 0;
}

static int socket_bridge(int fd1, int fd2)
{
	static const size_t len = 1024 * 1024;
	struct pollfd fds[2];
	int pipes[2] = {-1, -1};
	int ret;

	if (pipe(pipes)) {
		ret = errno;
		perror("pipe");
		return -ret;
	}

	fds[0].fd = fd1;
	fds[0].events = POLLIN | POLLPRI;
	fds[1].fd = fd2;
	fds[1].events = POLLIN | POLLPRI;

do_poll:
	if (atomic_load(&g_stop_app)) {
		ret = 0;
		goto out;
	}

	ret = poll(fds, 2, 1000);
	if (unlikely(ret < 0)) {
		ret = errno;
		perror("poll");
		goto out;
	}

	if (ret == 0)
		goto do_poll;

	if (fds[0].revents & POLLIN) {
		ret = recv_and_send(fd1, fd2, pipes, len);
		if (unlikely(ret < 0))
			goto out;
	}

	if (fds[1].revents & POLLIN) {
		ret = recv_and_send(fd2, fd1, pipes, len);
		if (unlikely(ret < 0))
			goto out;
	}
	goto do_poll;

out:
	if (pipes[0] != -1)
		close(pipes[0]);
	if (pipes[1] != -1)
		close(pipes[1]);
	return ret;
}

static void server_handle_private_conn(struct client_slot *slot)
{
	int fd_private = atomic_load(&slot->fd_private);
	int fd_client = slot->fd;

	socket_bridge(fd_private, fd_client);
	if (fd_client != -1)
		close(fd_client);
	if (fd_private != -1)
		close(fd_private);
	slot->fd = -1;
	atomic_store(&slot->fd_private, -1);
}

static void *_server_handle_client2(void *slot_p)
{
	struct client_slot *slot = (struct client_slot *)slot_p;
	struct server_data *data = slot->data;
	struct packet pkt;
	int fd_lost_client;
	ssize_t ret;

	data->map_lock.lock();
	data->map.emplace(gen_map_key(&slot->addr), slot);
	data->map_lock.unlock();

	pkt.type = PKT_TYPE_SERVER_GET_A_REAL_CLIENT;
	pkt.pad = 0;
	pkt.len = sizeof(slot->addr);
	memcpy(pkt.data, &slot->addr, sizeof(slot->addr));

	fd_lost_client = atomic_load(&data->fd_lost_client);
	if (unlikely(fd_lost_client == -1))
		goto out;

	ret = send(fd_lost_client, &pkt, sizeof(pkt), 0);
	if (unlikely(ret < 0)) {
		perror("send");
		goto out;
	}

	while (atomic_load(&slot->fd_private) == -1) {
		usleep(10000);
		if (atomic_load(&g_stop_app))
			goto out;
	}
	data->map_lock.lock();
	data->map.erase(gen_map_key(&slot->addr));
	data->map_lock.unlock();
	server_handle_private_conn(slot);
out:
	delete slot;
	return NULL;
}

static int server_handle_client2(int client_fd, struct sockaddr_in *addr,
				 struct server_data *data)
{
	struct client_slot *slot;
	pthread_t thread;
	int ret;

	slot = new struct client_slot;
	if (unlikely(!slot))
		return -ENOMEM;

	slot->fd = client_fd;
	slot->addr = *addr;
	slot->data = data;
	slot->fd_private = -1;
	ret = pthread_create(&thread, NULL, _server_handle_client2, slot);
	if (unlikely(ret)) {
		errno = ret;
		perror("pthread_create");
		delete slot;
		return -ret;
	}

	ret = pthread_detach(thread);
	if (unlikely(ret)) {
		errno = ret;
		perror("pthread_detach");
		return -ret;
	}

	return 0;
}

static int server_handle_socket2(struct server_data *data)
{
	struct sockaddr_in addr;
	int fd = data->fd2;
	socklen_t addrlen;
	int client_fd;
	int ret;

do_accept:
	if (atomic_load(&g_stop_app))
		return 0;

	addrlen = sizeof(addr);
	client_fd = accept(fd, (struct sockaddr *)&addr, &addrlen);
	if (unlikely(client_fd < 0)) {
		ret = errno;
		perror("accept");
		goto out;
	}
	setup_socket(client_fd);

	if (unlikely(atomic_load(&data->fd_lost_client) == -1)) {
		puts("The lost client is not connected, dropping...");
		close(client_fd);
		goto do_accept;
	}

	ret = server_handle_client2(client_fd, &addr, data);
	if (likely(!ret))
		goto do_accept;

out:
	atomic_store(&g_stop_app, true);
	return ret;
}

static void *server_handle_socket1(void *data_p)
{
	struct server_data *data = (struct server_data *)data_p;
	int tcp_fd = data->fd1;
	struct packet pkt;
	int client_fd;
	ssize_t ret;
	int tmp;

do_accept:
	if (atomic_load(&g_stop_app))
		return NULL;

	client_fd = accept(tcp_fd, NULL, NULL);
	if (unlikely(client_fd < 0)) {
		perror("accept");
		goto out;
	}
	setup_socket(client_fd);

	ret = recv(client_fd, &pkt, sizeof(pkt), 0);
	if (unlikely(ret <= 0)) {
		if (ret == 0) {
			puts("Client disconnected!");
			close(client_fd);
			goto do_accept;
		}

		perror("recv");
		close(client_fd);
		goto out;
	}

	if ((size_t)ret != sizeof(pkt)) {
		close(client_fd);
		goto do_accept;
	}

	switch (pkt.type) {
	case PKT_TYPE_CLIENT_INIT_CIRCUIT: {
		int fd_lost = atomic_load(&data->fd_lost_client);

		if (fd_lost != -1) {
			puts("Replacing the circuit with a new connection...");
			close(fd_lost);
		}

		atomic_store(&data->fd_lost_client, client_fd);
		puts("The \"lost client\" has been connected!");
		break;
	}
	case PKT_TYPE_CLIENT_START_PRIVATE_SOCK: {
		struct client_slot *slot = NULL;
		struct sockaddr_in addr;

		memcpy(&addr, &pkt.data, sizeof(addr));

		data->map_lock.lock();
		auto it = data->map.find(gen_map_key(&addr));
		if (it != data->map.end())
			slot = it->second;
		data->map_lock.unlock();

		if (slot)
			atomic_store(&slot->fd_private, client_fd);
		else
			close(client_fd);

		break;
	}
	default:
		close(client_fd);
		break;
	}
	goto do_accept;

out:
	tmp = atomic_load(&data->fd_lost_client);
	if (tmp != -1) {
		close(tmp);
		atomic_store(&data->fd_lost_client, -1);
	}
	atomic_store(&g_stop_app, true);
	return NULL;
}

static int run_server(const char *listen1_addr, uint16_t listen1_port,
		      const char *listen2_addr, uint16_t listen2_port)
{
	struct server_data data;
	pthread_t thread;
	int err = 0;

	data.fd1 = -1;
	data.fd2 = -1;
	atomic_store(&data.fd_lost_client, -1);

	data.fd1 = create_tcp_sock();
	if (unlikely(data.fd1 < 0)) {
		err = data.fd1;
		goto out;
	}

	data.fd2 = create_tcp_sock();
	if (unlikely(data.fd2 < 0)) {
		err = data.fd2;
		goto out;
	}

	err = bind_and_listen_tcp_sock(data.fd1, listen1_addr, listen1_port);
	if (unlikely(err < 0))
		goto out;

	err = bind_and_listen_tcp_sock(data.fd2, listen2_addr, listen2_port);
	if (unlikely(err < 0))
		goto out;

	err = pthread_create(&thread, NULL, server_handle_socket1, &data);
	if (unlikely(err)) {
		errno = err;
		perror("pthread_create");
		err = -err;
		goto out;
	}

	err = pthread_detach(thread);
	if (unlikely(err)) {
		errno = err;
		perror("pthread_detach");
		err = -err;
		goto out;
	}

	atomic_store(&g_stop_app, false);
	err = server_handle_socket2(&data);
out:
	if (data.fd1 != -1)
		close(data.fd1);
	if (data.fd2 != -1)
		close(data.fd2);
	puts("Closing the server...");
	return (err < 0) ? -err : err;
}

static int connect_tcp_sock(int fd, const char *addr, uint16_t port)
{
	struct sockaddr_in dst_addr;
	int err;

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(port);
	dst_addr.sin_addr.s_addr = inet_addr(addr);

	printf("Connecting to %s:%u...\n", addr, port);
	err = connect(fd, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
	if (err < 0) {
		err = errno;
		perror("connect");
		return -err;
	}
	err = setup_socket(fd);
	printf("Connected!\n");
	return 0;
}

struct client_private_data {
	struct packet	pkt;
	const char	*server_addr;
	const char	*target_addr;
	uint16_t	target_port;
	uint16_t	server_port;
};

static void *start_private_conn(void *pp)
{
	struct client_private_data *p = (struct client_private_data *)pp;
	int fd_pa = -1, fd_pb = -1;
	int err = 0;
	ssize_t ret;

	fd_pa = create_tcp_sock();
	if (unlikely(fd_pa < 0)) {
		err = fd_pa;
		goto out_free;
	}

	fd_pb = create_tcp_sock();
	if (unlikely(fd_pb < 0)) {
		err = fd_pb;
		goto out_free;
	}

	err = connect_tcp_sock(fd_pa, p->server_addr, p->server_port);
	if (unlikely(err))
		goto out_free;

	err = connect_tcp_sock(fd_pb, p->target_addr, p->target_port);
	if (unlikely(err))
		goto out_free;

	p->pkt.type = PKT_TYPE_CLIENT_START_PRIVATE_SOCK;
	ret = send(fd_pa, &p->pkt, sizeof(p->pkt), 0);
	if (unlikely(ret < 0)) {
		err = errno;
		perror("send");
		goto out_free;
	}

out_free:
	delete p;
	if (err)
		goto out;

	socket_bridge(fd_pa, fd_pb);
out:
	if (fd_pa == -1)
		close(fd_pa);
	if (fd_pb == -1)
		close(fd_pb);
	return NULL;
}

static int handle_private_conn(int fd_circuit, const char *target_addr,
			       uint16_t target_port, const char *server_addr,
			       uint16_t server_port)
{
	struct client_private_data *pp;
	struct packet pkt;
	pthread_t thread;
	ssize_t ret;
	int err;

do_recv:
	ret = recv(fd_circuit, &pkt, sizeof(pkt), 0);
	if (unlikely(ret <= 0)) {
		if (ret == 0) {
			puts("Server has been disconnected!");
			return -ENETDOWN;
		}
		err = errno;
		perror("recv");
		return -err;
	}

	pp = new struct client_private_data;
	if (unlikely(!pp))
		return -ENOMEM;

	pp->pkt = pkt;
	pp->server_addr = server_addr;
	pp->server_port = server_port;
	pp->target_addr = target_addr;
	pp->target_port = target_port;
	err = pthread_create(&thread, NULL, start_private_conn, pp);
	if (unlikely(ret < 0)) {
		errno = ret;
		perror("pthread_create");
		delete pp;
		return -ret;
	}
	pthread_detach(thread);

	if (!atomic_load(&g_stop_app))
		goto do_recv;

	return 0;
}

static int start_circuit(int fd_circuit)
{
	struct packet pkt;
	ssize_t ret;
	int err;

	memset(&pkt, 0, sizeof(pkt));
	pkt.type = PKT_TYPE_CLIENT_INIT_CIRCUIT;
	ret = send(fd_circuit, &pkt, sizeof(pkt), 0);
	if (unlikely(ret < 0)) {
		err = errno;
		perror("send");
		return -err;
	}
	return 0;
}

static int _run_client(const char *target_addr, uint16_t target_port,
		       const char *server_addr, uint16_t server_port)
{
	int fd_circuit = -1;
	int err;

	fd_circuit = create_tcp_sock();
	if (unlikely(fd_circuit < 0))
		return -fd_circuit;

	err = connect_tcp_sock(fd_circuit, server_addr, server_port);
	if (unlikely(err))
		goto out;

	err = start_circuit(fd_circuit);
	if (unlikely(err))
		goto out;

	err = handle_private_conn(fd_circuit, target_addr, target_port,
				  server_addr, server_port);
out:
	close(fd_circuit);
	return (err < 0) ? -err : err;
}

static int run_client(const char *target_addr, uint16_t target_port,
		      const char *server_addr, uint16_t server_port)
{
	int ret;

	atomic_store(&g_stop_app, false);

repeat:
	ret = _run_client(target_addr, target_port, server_addr, server_port);
	if (unlikely(ret)) {
		errno = ret;
		perror("_run_client()");
	}

	if (atomic_load(&g_stop_app))
		return ret;

	puts("Sleeing for 3 seconds...");
	sleep(3);
	goto repeat;
}

static int set_signal_handler(void)
{
	struct sigaction sa;
	int ret;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	if (unlikely(sigaction(SIGINT, &sa, NULL) < 0))
		goto err;
	if (unlikely(sigaction(SIGHUP, &sa, NULL) < 0))
		goto err;
	if (unlikely(sigaction(SIGTERM, &sa, NULL) < 0))
		goto err;

	sa.sa_handler = SIG_IGN;
	if (unlikely(sigaction(SIGPIPE, &sa, NULL) < 0))
		goto err;

	return 0;

err:
	ret = errno;
	perror("sigaction");
	return -ret;
}

/*
 * Usage:
 *  ./slc client 127.0.0.1 5555 123.123.123.123 9999
 *  ./slc server 123.123.123.123 9999 0.0.0.0 9998
 *
 * The real clients access 0.0.0.0 9998
 */
int main(int argc, const char *argv[])
{
	if (argc != 6)
		goto print_usage;

	setvbuf(stdout, NULL, _IOLBF, 4096);
	set_signal_handler();

	if (!strcmp(argv[1], "client"))
		return run_client(argv[2], (uint16_t)atoi(argv[3]),
				  argv[4], (uint16_t)atoi(argv[5]));

	if (!strcmp(argv[1], "server"))
		return run_server(argv[2], (uint16_t)atoi(argv[3]),
				  argv[4], (uint16_t)atoi(argv[5]));

print_usage:
	puts("SLC (Socket Lost Control) 0.0.1\n");
	puts("Usage:\n");
	printf("\t%s server [circuit_addr] [circuit_port] [public_addr] [public_port]\n", argv[0]);
	printf("\t%s client [target_addr] [target_port] [circuit_addr] [circuit_port]\n", argv[0]);
	puts("\n");
	puts("License: GNU GPL v2\n");
	puts("Copyright (C) 2022 Ammar Faizi <ammarfaizi2@gnuweeb.org>");
	puts("This is free software; see the source for copying conditions.  There is NO");
	puts("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
	return 1;
}
