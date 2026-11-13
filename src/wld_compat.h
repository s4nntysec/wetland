/*
 * wetland — platform compatibility shim.
 *
 * Papers over the differences between POSIX sockets and Winsock so the relay
 * and the networking helpers build unchanged on Linux, macOS and Windows.
 * Socket file descriptors are kept as plain `int` throughout the codebase;
 * on Windows that holds a SOCKET cast to int (fine for the handle values we
 * ever see).
 */
#ifndef WLD_COMPAT_H
#define WLD_COMPAT_H 1

#ifdef _WIN32

#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <stddef.h>

typedef WSAPOLLFD wld_pollfd;
#  define wld_poll(fds, n, to) WSAPoll((fds), (ULONG)(n), (to))
#  define SOCKET_CAST SOCKET

#  ifndef SHUT_RD
#    define SHUT_RD   SD_RECEIVE
#  endif
#  ifndef SHUT_WR
#    define SHUT_WR   SD_SEND
#  endif
#  ifndef SHUT_RDWR
#    define SHUT_RDWR SD_BOTH
#  endif

#  define wld_closesocket(fd) closesocket((SOCKET)(fd))

#  ifndef STDIN_FILENO
#    define STDIN_FILENO  0
#  endif
#  ifndef STDOUT_FILENO
#    define STDOUT_FILENO 1
#  endif
#  ifndef STDERR_FILENO
#    define STDERR_FILENO 2
#  endif

static inline long
wld_sock_read(int fd, void *b, size_t n)
{
	return recv((SOCKET)fd, (char *)b, (int)n, 0);
}
static inline long
wld_sock_write(int fd, const void *b, size_t n)
{
	return send((SOCKET)fd, (const char *)b, (int)n, 0);
}
static inline int
wld_wouldblock(void)
{
	return WSAGetLastError() == WSAEWOULDBLOCK;
}
static inline int
wld_eintr(void)
{
	return 0; /* Winsock calls are not interrupted like POSIX EINTR */
}

#else /* POSIX */

#  include <poll.h>
#  include <errno.h>
#  include <unistd.h>
#  include <sys/socket.h>

typedef struct pollfd wld_pollfd;
#  define wld_poll(fds, n, to) poll((fds), (n), (to))
#  define SOCKET_CAST int

#  define wld_closesocket(fd) close(fd)

static inline long
wld_sock_read(int fd, void *b, size_t n)
{
	return read(fd, b, n);
}
static inline long
wld_sock_write(int fd, const void *b, size_t n)
{
	return write(fd, b, n);
}
static inline int
wld_wouldblock(void)
{
	return errno == EAGAIN || errno == EWOULDBLOCK;
}
static inline int
wld_eintr(void)
{
	return errno == EINTR;
}

#endif

/* Initialise/shut down the networking subsystem (WSAStartup on Windows). */
int  wld_net_startup(void);
void wld_net_cleanup(void);

#endif /* WLD_COMPAT_H */
