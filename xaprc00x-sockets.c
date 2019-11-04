// SPDX-License-Identifier: GPL-2.0+
/**
 * @file xaprc00x_sockets.c
 * @brief Implementation of the host sockets API for SCM. These functions
 *	operate the outbound sockets to provide virtual ownership to the USB
 *	device.
 */

#include <linux/rhashtable.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>

struct scm_host_socket {
	int sock_id;
	struct socket *sock;
	struct rhash_head hash;
};

static struct rhashtable socket_hash_table = {0};

static struct rhashtable_params ht_parms = {
	.nelem_hint = 8,
	.key_len = sizeof(int),
	.key_offset = offsetof(struct scm_host_socket, sock_id),
	.head_offset = offsetof(struct scm_host_socket, hash),
};

int xaprc00x_socket_mgr_init(void)
{
	return rhashtable_init(&socket_hash_table, &ht_parms);
}

/**
 * xaprc00x_get_socket - Retrieves a stored socket
 *
 * @table The table to search
 * @params The tables parameters
 * @key The key to search the table for
 *
 * Returns: Number of bytes received or an error code.
 */
static struct scm_host_socket *xaprc00x_get_socket(int *key)
{
	return rhashtable_lookup_fast(&socket_hash_table, key, ht_parms);
}

/**
 * xaprc00x_socket_create - Creates a sock for a given family and protocol
 *
 * @socket_id The socket id to connect
 * @family The protocol family of the connection
 * @protocol The protocol to connect with
 *
 * Creates a sock for a given family and protocol which can be referneced by
 * the given sock_id
 *
 * Notes: Currently only supports INET and INET6 address families
 * and TCP protocols.
 *
 * Returns: 0 if all endpoints were matched, -ENXIO otherwise
 */
int xaprc00x_socket_create(int socket_id, int family, int protocol)
{
	int ret;
	struct socket *sock = NULL;
	struct scm_host_socket *scm_sock;

	/* Prevent overwriting an existing socket */
	if (xaprc00x_get_socket(&socket_id)) {
		ret = -EEXIST;
		goto exit;
	}

	/* Create the outbound socket */
	ret = sock_create_kern(&init_net, family, SOCK_STREAM, protocol,
		&sock);
	if (ret)
		goto exit;

	/* Register the socket on the table */
	scm_sock = kzalloc(sizeof(struct scm_host_socket), GFP_KERNEL);
	scm_sock->sock = sock;
	rhashtable_lookup_insert_fast(&socket_hash_table, &scm_sock->hash,
		ht_parms);
exit:
	return ret;
}

/**
 * xaprc00x_socket_close - Closes a sock
 *
 * @socket_id The socket id to close
 */
void xaprc00x_socket_close(int socket_id)
{
	struct scm_host_socket *socket;
	/* Close and free the given socket if it can be found */
	socket = xaprc00x_get_socket(&socket_id);
	if (socket) {
		rhashtable_remove_fast(&socket_hash_table, &socket->hash,
			ht_parms);
		sock_release(socket->sock);
		kfree(socket);
	}
}

/**
 * xaprc00x_socket_create - Creates a sock for a given family and protocol
 *
 * @socket_id The socket id to connect
 * @how The direction to shut down
 */
void xaprc00x_socket_shutdown(int socket_id, enum sock_shutdown_cmd how)
{
	struct scm_host_socket *socket;
	/* Close the given socket if it can be found */
	socket = xaprc00x_get_socket(&socket_id);
	if (socket)
		kernel_sock_shutdown(socket->sock, how);
}

/**
 * xaprc00x_addr_in4 - Assemble an in4 address
 *
 * @ip_addr The buffer containing the IPv4 address in network byte order.
 * @ip_len The length of the address being passed
 * @port The port to connect to
 * @addr The in4 address to write to
 *
 * Populates an inet4 address
 *
 * Returns: 0 on success or an error code
 */
static int xaprc00x_addr_in4(char *ip_addr, int ip_len, __be16 port,
	struct sockaddr_in *addr)
{
	int ret = -EINVAL;

	if (addr && ip_addr && ip_len == sizeof(struct in_addr)) {
		addr->sin_family = AF_INET;
		addr->sin_port = port;
		memcpy(&addr->sin_addr, ip_addr, ip_len);
		ret = 0;
	}
	return ret;
}

/**
 * xaprc00x_addr_in6 - Assemble an in6 address
 *
 * @addrBuf The buffer containing the IPv6 address
 * @addrLen The length of the address being passed
 * @port The port to connect to
 * @flow The flow information
 * @scope The scope information
 * @addr The in6 address to write to
 *
 * Populates an inet6 address
 *
 * Returns: 0 on success or an error code
 */
static int xaprc00x_addr_in6(char *ip_addr,
	int ip_len, __be16 port, __be32 flow, __u32 scope,
	struct sockaddr_in6 *addr)
{
	int ret = -EINVAL;

	if (addr && ip_addr && ip_len == sizeof(struct in6_addr)) {
		addr->sin6_family = AF_INET6;
		addr->sin6_scope_id = scope;
		addr->sin6_port = port;
		addr->sin6_flowinfo = flow;
		memcpy(&addr->sin6_addr, ip_addr, ip_len);
		ret = 0;
	}
	return ret;
}

/**
 * xaprc00x_socket_connect_in4 - Connect an existing socket to an INET address
 *
 * @socket_id The socket id to connect
 * @addr The inet address (4 bytes) to connect to, in network byte order
 * @port The port to connect to in notwork byte order
 * @flags Flags to pass to kernel_connect
 *
 * Connects a managed socket to a given address.
 *
 * Returns: Result from xaprc00x_socket_connect
 */
int xaprc00x_socket_connect_in4(int socket_id, char *ip_addr, int ip_len,
	__be16 port, int flags)
{
	struct sockaddr_in addr = {0};
	struct scm_host_socket *socket;
	int ret = 0;

	socket = xaprc00x_get_socket(&socket_id);
	if (!socket) {
		ret = -EEXIST;
		goto exit;
	}

	ret = xaprc00x_addr_in4(ip_addr, ip_len, port, &addr);

	if (!ret)
		ret = kernel_connect(socket->sock, (struct sockaddr *)&addr,
			sizeof(struct sockaddr_in), flags);
exit:
	return ret;
}

/**
 * xaprc00x_socket_connect_in6 - Connect an existing socket to an INET6 address
 *
 * @socket_id The socket id to connect
 * @addr The inet6 address (16 bytes) to connect to, in network byte order
 * @port The port to connect to in notwork byte order
 * @flags Flags to pass to kernel_connect
 *
 * Connects a managed socket to a given address.
 *
 * Returns: 0 on success or an error code
 */
int xaprc00x_socket_connect_in6(int socket_id, char *ip_addr, int ip_len,
	__be16 port, __be32 flow, __u32 scope, int flags)
{
	struct sockaddr_in6 addr = {0};
	struct scm_host_socket *socket;
	int ret = 0;

	socket = xaprc00x_get_socket(&socket_id);
	if (!socket) {
		ret = -EEXIST;
		goto exit;
	}

	ret = xaprc00x_addr_in6(ip_addr, ip_len, port, flow, scope,
		&addr);
	if (!ret)
		ret = kernel_connect(socket->sock, (struct sockaddr *)&addr,
			sizeof(struct in6_addr), flags);
exit:
	return ret;
}

/**
 * xaprc00x_socket_write - Writes to a socket
 *
 * @socket_id The socket id to connect
 * @buf The buffer to write
 * @len The length in bytes of the buffer
 *
 * Returns: Number of bytes transmitted or an error code.
 */
int xaprc00x_socket_write(int socket_id, void *buf, int len)
{
	struct scm_host_socket *socket;
	int ret = -EEXIST;
	struct msghdr msg;
	struct kvec vec;

	socket = xaprc00x_get_socket(&socket_id);
	if (socket) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		vec.iov_len = len;
		vec.iov_base = buf;

		ret = kernel_sendmsg(socket->sock, &msg, &vec, len, len);
	}
	return ret;
}

/**
 * xaprc00x_socket_read - Writes to a socket
 *
 * @socket_id The socket id to connect
 * @buf The buffer to write
 * @len The length in bytes of the buffer
 * @flags Flags to pass to kernel_recvmsg
 *
 * Returns: Number of bytes received or an error code.
 */
int xaprc00x_socket_read(int socket_id, void *buf, int len, int flags)
{
	struct scm_host_socket *socket;
	struct msghdr msg;
	struct kvec vec;
	int ret = -EEXIST;

	socket = xaprc00x_get_socket(&socket_id);
	if (socket) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		vec.iov_len = len;
		vec.iov_base = buf;

		ret = kernel_recvmsg(socket->sock, &msg, &vec, len, len, 0);
	}
	return ret;
}
