#include "wld_net.h"
#include "wld_compat.h"

#include <string.h>

#ifdef _WIN32
#  include <stdint.h>
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/socket.h>
#endif

int
wld_net_startup(void)
{
#ifdef _WIN32
	WSADATA wsa;
	return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
#else
	return 0;
#endif
}

void
wld_net_cleanup(void)
{
#ifdef _WIN32
	WSACleanup();
#endif
}

int
wld_set_nonblock(int fd, int on)
{
#ifdef _WIN32
	u_long mode = on ? 1 : 0;
	return ioctlsocket((SOCKET)fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0)
		return -1;
	if (on)
		fl |= O_NONBLOCK;
	else
		fl &= ~O_NONBLOCK;
	return fcntl(fd, F_SETFL, fl);
#endif
}

void
wld_set_keepalive(int fd)
{
	int on = 1;
	setsockopt((SOCKET_CAST)fd, SOL_SOCKET, SO_KEEPALIVE,
	           (const char *)&on, sizeof on);
}

int
wld_read_all(int fd, void *buf, size_t n)
{
	uint8_t *p = buf;
	size_t off = 0;
	while (off < n) {
		long r = wld_sock_read(fd, p + off, n - off);
		if (r < 0) {
			if (wld_eintr())
				continue;
			return -1;
		}
		if (r == 0)
			return -1; /* EOF before n bytes */
		off += (size_t)r;
	}
	return 0;
}

int
wld_write_all(int fd, const void *buf, size_t n)
{
	const uint8_t *p = buf;
	size_t off = 0;
	while (off < n) {
		long w = wld_sock_write(fd, p + off, n - off);
		if (w < 0) {
			if (wld_eintr())
				continue;
			return -1;
		}
		off += (size_t)w;
	}
	return 0;
}

int
wld_tcp_connect(const char *host, const char *port)
{
	struct addrinfo hints, *res = NULL, *rp;
	int fd = -1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port, &hints, &res) != 0)
		return -1;

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;
		if (connect((SOCKET_CAST)fd, rp->ai_addr, (int)rp->ai_addrlen) == 0)
			break;
		wld_closesocket(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd >= 0)
		wld_set_keepalive(fd);
	return fd;
}

int
wld_tcp_listen(const char *host, const char *port, int backlog)
{
	struct addrinfo hints, *res = NULL, *rp;
	int fd = -1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(host, port, &hints, &res) != 0)
		return -1;

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		int on = 1;
		fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;
		setsockopt((SOCKET_CAST)fd, SOL_SOCKET, SO_REUSEADDR,
		           (const char *)&on, sizeof on);
		if (bind((SOCKET_CAST)fd, rp->ai_addr, (int)rp->ai_addrlen) == 0 &&
		    listen((SOCKET_CAST)fd, backlog) == 0)
			break;
		wld_closesocket(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}
