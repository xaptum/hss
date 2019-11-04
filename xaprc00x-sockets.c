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
 * xaprc00x_close_socket - Closes a sock
 *
 * @socket_id The socket id to close
 */
void xaprc00x_close_socket(int socket_id)
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
void xaprc00x_shutdown_socket(int socket_id, enum sock_shutdown_cmd how)
{
	struct scm_host_socket *socket;
	/* Close the given socket if it can be found */
	socket = xaprc00x_get_socket(&socket_id);
	if (socket)
		kernel_sock_shutdown(socket->sock, how);
}

/**
 * xaprc00x_socket_connect - Connect an existing socket to an address
 *
 * @socket_id The socket id to connect
 * @family The protocol family of the connection
 * @protocol The protocol to connect with
 * @addrBuf The address to connect to in network byte order
 * @ipaddr_len The length of the address in bytes
 * @port The port to connect to in notwork byte order
 * @flow The flowinfo in network byte order (ignored unless family is INET6)
 * @scope The scope in network byte order (ignored unless family is INET6)
 * @flags Flags to pass to kernel_connect
 *
 * Connects a managed socket to a given address.
 *
 * Notes: Currently only supports INET and INET6 address families.
 *
 * Returns: 0 if all endpoints were matched, -ENXIO otherwise
 */
int xaprc00x_socket_connect(int socket_id, unsigned short int family,
	char *addrBuf, int ipaddr_len, __be16 port, __be32 flow, __u32 scope,
	int flags)
{
	int ret;
	struct scm_host_socket *socket;
	struct sockaddr_storage addr = {0};
	int sockaddr_len;

	ret = 0;

	if (!addrBuf) {
		ret = -EINVAL;
		goto exit;
	}

	/* Make sure the requested socket exists */
	socket = xaprc00x_get_socket(&socket_id);

	if (!socket) {
		ret = -ENXIO;
		goto exit;
	}

	/* Create the address if the family is supported */
	if (family == AF_INET && ipaddr_len == sizeof(struct in_addr)) {
		struct sockaddr_in *dst_in4 = (struct sockaddr_in *) &addr;

		sockaddr_len = sizeof(struct sockaddr_in);

		dst_in4->sin_family = family;
		dst_in4->sin_port = port;
		memcpy(&dst_in4->sin_addr, addrBuf, ipaddr_len);
	} else if (family == AF_INET6 &&
		ipaddr_len == sizeof(struct in6_addr)) {
		struct sockaddr_in6 *dst_in6 = (struct sockaddr_in6 *) &addr;

		sockaddr_len = sizeof(struct sockaddr_in6);

		dst_in6->sin6_family = family;
		dst_in6->sin6_scope_id = scope;
		dst_in6->sin6_port = port;
		dst_in6->sin6_flowinfo = flow;
		memcpy(&dst_in6->sin6_addr, addrBuf, ipaddr_len);
	} else {
		/* Invalid protocol or address specified */
		ret = -EINVAL;
		goto exit;
	}

	ret = kernel_connect(socket->sock, (struct sockaddr *)&addr,
		sockaddr_len, flags);
exit:
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
int xaprc00x_socket_connect_in4(int socket_id, char *addr, __be16 port,
	int flags)
{
	return xaprc00x_socket_connect(socket_id, AF_INET, addr,
		sizeof(struct in_addr), port, 0, 0, flags);
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
 * Returns: Result from xaprc00x_socket_connect
 */
int xaprc00x_socket_connect_in6(int socket_id, unsigned short int family,
	char *addr, __be16 port, __be32 flow, __u32 scope, int flags)
{
	return xaprc00x_socket_connect(socket_id, AF_INET6, addr,
		sizeof(struct in6_addr), port, flow, scope, flags);
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
