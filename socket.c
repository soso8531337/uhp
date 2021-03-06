/*
 * socket.c
 *
 * Copyright (C) 2012 Martin Szulecki <m.szulecki@libimobiledevice.org>
 * Copyright (C) 2012 Nikias Bassen <nikias@gmx.li>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
static int wsa_init = 0;
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif
#include "socket.h"
#include "log.h"

#define RECV_TIMEOUT 20000

#ifndef WIN32
int socket_create_unix(const char *filename)
{
	struct sockaddr_un name;
	int sock;
	size_t size;
#ifdef SO_NOSIGPIPE
	int yes = 1;
#endif

	// remove if still present
	unlink(filename);

	/* Create the socket. */
	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		usbmuxd_log(LL_ERROR, "Create Socket Error:%s", strerror(errno));
		return -1;
	}

#ifdef SO_NOSIGPIPE
	if (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "setsockopt Error:%s", strerror(errno));
		socket_close(sock);
		return -1;
	}
#endif

	/* Bind a name to the socket. */
	name.sun_family = AF_LOCAL;
	strncpy(name.sun_path, filename, sizeof(name.sun_path));
	name.sun_path[sizeof(name.sun_path) - 1] = '\0';

	/* The size of the address is
	   the offset of the start of the filename,
	   plus its length,
	   plus one for the terminating null byte.
	   Alternatively you can just do:
	   size = SUN_LEN (&name);
	 */
	size = (offsetof(struct sockaddr_un, sun_path)
			+ strlen(name.sun_path) + 1);

	if (bind(sock, (struct sockaddr *) &name, size) < 0) {
		usbmuxd_log(LL_ERROR, "bind Error:%s", strerror(errno));
		socket_close(sock);
		return -1;
	}

	if (listen(sock, 10) < 0) {
		usbmuxd_log(LL_ERROR, "listen Error:%s", strerror(errno));
		socket_close(sock);
		return -1;
	}

	return sock;
}

int socket_connect_unix(const char *filename)
{
	struct sockaddr_un name;
	int sfd = -1;
	size_t size;
	struct stat fst;
#ifdef SO_NOSIGPIPE
	int yes = 1;
#endif

	// check if socket file exists...
	if (stat(filename, &fst) != 0) {
		usbmuxd_log(LL_ERROR, "stat '%s': %s\n", filename,
					strerror(errno));
		return -1;
	}
	// ... and if it is a unix domain socket
	if (!S_ISSOCK(fst.st_mode)) {
			usbmuxd_log(LL_ERROR, "File '%s' is not a socket!\n",
					filename);
		return -1;
	}
	// make a new socket
	if ((sfd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
		usbmuxd_log(LL_ERROR, "Create socket: %s\n", strerror(errno));
		return -1;
	}

#ifdef SO_NOSIGPIPE
	if (setsockopt(sfd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "setsockopt Error:%s", strerror(errno));
		socket_close(sfd);
		return -1;
	}
#endif

	// and connect to 'filename'
	name.sun_family = AF_LOCAL;
	strncpy(name.sun_path, filename, sizeof(name.sun_path));
	name.sun_path[sizeof(name.sun_path) - 1] = 0;

	size = (offsetof(struct sockaddr_un, sun_path)
			+ strlen(name.sun_path) + 1);

	if (connect(sfd, (struct sockaddr *) &name, size) < 0) {
		socket_close(sfd);
		usbmuxd_log(LL_ERROR, "connect: %s\n", 
					strerror(errno));
		return -1;
	}

	return sfd;
}
#endif

int socket_create(uint16_t port)
{
	int sfd = -1;
	int yes = 1;
#ifdef WIN32
	WSADATA wsa_data;
	if (!wsa_init) {
		if (WSAStartup(MAKEWORD(2,2), &wsa_data) != ERROR_SUCCESS) {
			fprintf(stderr, "WSAStartup failed!\n");
			ExitProcess(-1);
		}
		wsa_init = 1;
	}
#endif
	struct sockaddr_in saddr;

	if (0 > (sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP))) {
		usbmuxd_log(LL_ERROR, "Create socket: %s\n", strerror(errno));
		return -1;
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "setsockopt Error:%s", strerror(errno));
		socket_close(sfd);
		return -1;
	}

#ifdef SO_NOSIGPIPE
	if (setsockopt(sfd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "setsockopt Error:%s", strerror(errno));
		socket_close(sfd);
		return -1;
	}
#endif

	memset((void *) &saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(port);

	if (0 > bind(sfd, (struct sockaddr *) &saddr, sizeof(saddr))) {
		usbmuxd_log(LL_ERROR, "bind Error:%s", strerror(errno));
		socket_close(sfd);
		return -1;
	}

	if (listen(sfd, 1) == -1) {
		usbmuxd_log(LL_ERROR, "listen Error:%s", strerror(errno));
		socket_close(sfd);
		return -1;
	}

	return sfd;
}

int socket_connect(const char *addr, uint16_t port)
{
	int sfd = -1;
	int yes = 1;
	struct hostent *hp;
	struct sockaddr_in saddr;
#ifdef WIN32
	WSADATA wsa_data;
	if (!wsa_init) {
		if (WSAStartup(MAKEWORD(2,2), &wsa_data) != ERROR_SUCCESS) {
			fprintf(stderr, "WSAStartup failed!\n");
			ExitProcess(-1);
		}
		wsa_init = 1;
	}
#endif

	if (!addr) {
		errno = EINVAL;
		return -1;
	}

	if ((hp = gethostbyname(addr)) == NULL) {
		usbmuxd_log(LL_ERROR,"unknown host '%s'", addr);
		return -1;
	}

	if (!hp->h_addr) {
		usbmuxd_log(LL_ERROR,"gethostbyname returned NULL address!");
		return -1;
	}

	if (0 > (sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP))) {
		usbmuxd_log(LL_ERROR, "Create socket: %s\n", strerror(errno));
		return -1;
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "setsockopt socket: %s\n", strerror(errno));
		socket_close(sfd);
		return -1;
	}

#ifdef SO_NOSIGPIPE
	if (setsockopt(sfd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "setsockopt socket: %s\n", strerror(errno));
		socket_close(sfd);
		return -1;
	}
#endif

	memset((void *) &saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = *(uint32_t *) hp->h_addr;
	saddr.sin_port = htons(port);

	if (connect(sfd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		usbmuxd_log(LL_ERROR, "connect socket: %s\n", strerror(errno));
		socket_close(sfd);
		return -2;
	}

	return sfd;
}

int socket_check_fd(int fd, fd_mode fdm, unsigned int timeout)
{
	fd_set fds;
	int sret;
	int eagain;
	struct timeval to;
	struct timeval *pto;

	if (fd < 0) {
		usbmuxd_log(LL_ERROR, "ERROR: invalid fd in check_fd %d", fd);
		return -1;
	}

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	if (timeout > 0) {
		to.tv_sec = (time_t) (timeout / 1000);
		to.tv_usec = (time_t) ((timeout - (to.tv_sec * 1000)) * 1000);
		pto = &to;
	} else {
		pto = NULL;
	}

	sret = -1;

	do {
		eagain = 0;
		switch (fdm) {
		case FDM_READ:
			sret = select(fd + 1, &fds, NULL, NULL, pto);
			break;
		case FDM_WRITE:
			sret = select(fd + 1, NULL, &fds, NULL, pto);
			break;
		case FDM_EXCEPT:
			sret = select(fd + 1, NULL, NULL, &fds, pto);
			break;
		default:
			return -1;
		}

		if (sret < 0) {
			switch (errno) {
			case EINTR:
				// interrupt signal in select
				usbmuxd_log(LL_DEBUG, "EINTR");
				eagain = 1;
				break;
			case EAGAIN:					
				usbmuxd_log(LL_DEBUG, "EAGAIN");
				break;
			default:
				usbmuxd_log(LL_ERROR, "select failed: %s\n", strerror(errno));
				return -1;
			}
		}
	} while (eagain);

	return sret;
}

int socket_accept(int fd, uint16_t port)
{
#ifdef WIN32
	int addr_len;
#else
	socklen_t addr_len;
#endif
	int result;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	addr_len = sizeof(addr);
	result = accept(fd, (struct sockaddr*)&addr, &addr_len);

	return result;
}

int socket_shutdown(int fd, int how)
{
	return shutdown(fd, how);
}

int socket_close(int fd) {
#ifdef WIN32
	return closesocket(fd);
#else
	return close(fd);
#endif
}

int socket_receive(int fd, void *data, size_t length)
{
	return socket_receive_timeout(fd, data, length, 0, RECV_TIMEOUT);
}

int socket_peek(int fd, void *data, size_t length)
{
	return socket_receive_timeout(fd, data, length, MSG_PEEK, RECV_TIMEOUT);
}

int socket_receive_timeout(int fd, void *data, size_t length, int flags,
					 unsigned int timeout)
{
	int res;
	int result;

	// check if data is available
	res = socket_check_fd(fd, FDM_READ, timeout);
	if (res <= 0) {
		return res;
	}
	// if we get here, there _is_ data available
	result = recv(fd, data, length, flags);
	if (res > 0 && result == 0) {
		// but this is an error condition		
		usbmuxd_log(LL_DEBUG, "fd=%d recv returned 0", fd);
		return -EAGAIN;
	}
	if (result < 0) {
		return -errno;
	}
	return result;
}

int socket_send(int fd, void *data, size_t length)
{
	int flags = 0;
#ifdef MSG_NOSIGNAL
	flags |= MSG_NOSIGNAL;
#endif
	return send(fd, data, length, flags);
}
