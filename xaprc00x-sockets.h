/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file xaprc00x_sockets.h
 * @brief External functions for the SCM host socket manager.
 */
#ifndef __XAPRC00X_SOCKETS_H
#define __XAPRC00X_SOCKETS_H

int xaprc00x_socket_mgr_init(void);

int xaprc00x_socket_create(int socket_id, unsigned short int family,
	int protocol);

void xaprc00x_close_socket(int socket_id);

void xaprc00x_shutdown_socket(int socket_id, int dir);

int xaprc00x_socket_connect_in4(int socket_id, char *addr, int addrlen,
	__be16 port, int flags);

int xaprc00x_socket_connect_in6(int socket_id, char *addr, int addrlen, 
	__be16 port, __be32 flow, __u32 scope, int flags);

int xaprc00x_socket_write(int socket_id, void *const buf, int len);

int xaprc00x_socket_read(int socket_id, void *buf, int size, int flags);

#endif /* __XAPRC00X_SOCKETS_H */
