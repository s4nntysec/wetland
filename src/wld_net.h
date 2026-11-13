/* wetland — small socket/IO helpers */
#ifndef WLD_NET_H
#define WLD_NET_H 1

#include <stddef.h>
#include <sys/types.h>

/* Set O_NONBLOCK on/off. Returns 0 on success. */
int wld_set_nonblock(int fd, int on);

/* Enable TCP keepalive (best-effort). */
void wld_set_keepalive(int fd);

/* Read/write exactly n bytes on a blocking fd, retrying on EINTR/partial IO.
 * Return 0 on success, -1 on error or premature EOF. */
int wld_read_all(int fd, void *buf, size_t n);
int wld_write_all(int fd, const void *buf, size_t n);

/* Connect to host:port over TCP. Returns fd or -1. */
int wld_tcp_connect(const char *host, const char *port);

/* Create a listening TCP socket bound to host (NULL = all) : port.
 * Returns fd or -1. */
int wld_tcp_listen(const char *host, const char *port, int backlog);

#endif /* WLD_NET_H */
