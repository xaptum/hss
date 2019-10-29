/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file xaprc00x_sockets.c
 * @brief Implementation of the host sockets API for SCM. These functions
 *	operate the outbound sockets to provide virtual ownership to the USB
 *	device.
 */

int xaprc00x_create_socket(int socket_id, int family, int protocol)
{
	return 0;
}

void xaprc00x_close_socket(int socket_id)
{
	return;
}

void xaprc00x_shutdown_socket(int socket_id)
{
	return;
}

int xaprc00x_connect_socket(int socket_id, int family, char *const addr,
	int flow, int scope)
{
	return 0;
}

int xaprc00x_write_socket(int socket_id, void *const buf, int len)
{
	return 0;
}

int xaprc00x_read_socket(int socket_id, void *buf, int size, int flags)
{
	return 0;
}