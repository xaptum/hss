/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file xaprc00x_sockets.h
 * @brief External functions for the SCM host socket manager.
 */
#ifndef __XAPRC00X_SOCKETS_H
#define __XAPRC00X_SOCKETS_H

int xaprc00x_create_socket(int socket_id, int family, int protocol);

void xaprc00x_close_socket(int socket_id);

void xaprc00x_shutdown_socket(int socket_id);

int xaprc00x_connect_socket(int socket_id, int family, char *const addr,
	int flow, int scope);

int xaprc00x_write_socket(int socket_id, void *const buf, int len);

int xaprc00x_read_socket(int socket_id, void *buf, int size, int flags);

#endif /* __XAPRC00X_SOCKETS_H */
