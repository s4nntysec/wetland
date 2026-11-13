#include "wld_net.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

int
wld_set_nonblock(int fd, int on)
{
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0)
		return -1;
	if (on)
		fl |= O_NONBLOCK;
	else
		fl &= ~O_NONBLOCK;
	return fcntl(fd, F_SETFL, fl);
}

void
wld_set_keepalive(int fd)
{
	int on = 1;
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
}

int
wld_read_all(int fd, void *buf, size_t n)
{
	uint8_t *p = buf;
	size_t off = 0;
	while (off < n) {
		ssize_t r = read(fd, p + off, n - off);
		if (r < 0) {
			if (errno == EINTR)
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
		ssize_t w = write(fd, p + off, n - off);
		if (w < 0) {
			if (errno == EINTR)
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
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(fd);
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
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 &&
		    listen(fd, backlog) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}
