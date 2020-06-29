// SPDX-License-Identifier: GPL-2.0+
/**
 * @file hss_sockets.c
 * @brief Implementation of the host sockets API for HSS. These functions
 *	operate the outbound sockets to provide virtual ownership to the USB
 *	device.
 */

#include <linux/rhashtable.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>

struct hss_host_socket {
	int sock_id;
	struct socket *sock;
	struct rhash_head hash;
};

static struct rhashtable_params ht_parms = {
	.nelem_hint = 8,
	.key_len = sizeof(int),
	.key_offset = offsetof(struct hss_host_socket, sock_id),
	.head_offset = offsetof(struct hss_host_socket, hash),
};

int hss_socket_mgr_init(struct rhashtable **table)
{
	struct rhashtable *new_table;
	int ret;

	new_table = kzalloc(sizeof(struct rhashtable), GFP_KERNEL);
	/* Init a new hash table */
	ret = rhashtable_init(new_table, &ht_parms);
	if (!ret)
		*table = new_table;
	else
		kfree(new_table);
	return ret;
}

static void hss_socket_free(struct hss_host_socket *socket)
{
	sock_release(socket->sock);
	kfree(socket);
}

/**
 * hss_socket_mgr_destroy - Deallocate a socket
 *
 * @table The table to search
 * @params The tables parameters
 * @key The key to search the table for
 *
 * Returns: Number of bytes received or an error code.
 */
void hss_socket_mgr_destroy(struct rhashtable *socket_ht)
{
	const struct bucket_table *tbl;
	struct hss_host_socket *sk;
	struct rhash_head *pos;
	int i;

	rcu_read_lock();
	tbl = rht_dereference_rcu(socket_ht->tbl, socket_ht);
	for (i = 0; i < tbl->size; i++) {
		rht_for_each_entry_rcu(sk, pos, tbl, i, hash) {
			hss_socket_free(sk);
		}
	}
	rcu_read_unlock();

	/* Destroy and clear the hash table */
	rhashtable_destroy(socket_ht);
	kfree(socket_ht);
}

/**
 * hss_get_socket - Retrieves a stored socket
 *
 * @table The table to search
 * @params The tables parameters
 * @key The key to search the table for
 *
 * Returns: Number of bytes received or an error code.
 */
static struct hss_host_socket *hss_get_socket(int *key,
	struct rhashtable *socket_ht)
{
	return rhashtable_lookup_fast(socket_ht, key, ht_parms);
}

int hss_socket_exists(int key, struct rhashtable *socket_ht)
{
	return (hss_get_socket(&key, socket_ht) != NULL);
}

/**
 * hss_socket_create - Creates a sock for a given family and protocol
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
 * Returns: 0 on successor an error code
 */
int hss_socket_create(int socket_id, int family, int type, int protocol,
	struct rhashtable *socket_ht)
{
	int ret;
	struct socket *sock = NULL;
	struct hss_host_socket *hss_sock;

	/* Prevent overwriting an existing socket */
	if (hss_get_socket(&socket_id, socket_ht)) {
		ret = -EEXIST;
		goto exit;
	}

	/* Create the outbound socket */
	ret = sock_create_kern(&init_net, family, type, protocol,
		&sock);
	if (ret)
		goto exit;

	/* Register the socket on the table */
	hss_sock = kzalloc(sizeof(struct hss_host_socket), GFP_ATOMIC);
	if (!hss_sock) {
		ret = -ENOMEM;
		sock_release(sock);
	} else {
		hss_sock->sock_id = socket_id;
		hss_sock->sock = sock;
		rhashtable_lookup_insert_fast(socket_ht,
			&hss_sock->hash, ht_parms);
		ret = 0;
	}
exit:
	return ret;
}

/**
 * hss_socket_close - Closes a sock
 *
 * @socket_id The socket id to close
 */
void hss_socket_close(int socket_id, struct rhashtable *socket_ht)
{
	struct hss_host_socket *socket;

	/* Close and free the given socket if it can be found */
	socket = hss_get_socket(&socket_id, socket_ht);
	if (socket) {
		rhashtable_remove_fast(socket_ht, &socket->hash, ht_parms);
		hss_socket_free(socket);
	}
}

/**
 * hss_addr_in4 - Assemble an in4 address
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
static int hss_addr_in4(char *ip_addr, int ip_len, __be16 port,
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
 * hss_addr_in6 - Assemble an in6 address
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
static int hss_addr_in6(char *ip_addr,
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
 * hss_socket_connect_in4 - Connect an existing socket to an INET address
 *
 * @socket_id The socket id to connect
 * @addr The inet address (4 bytes) to connect to, in network byte order
 * @port The port to connect to in notwork byte order
 * @flags Flags to pass to kernel_connect
 *
 * Connects a managed socket to a given address.
 *
 * Returns: Result from hss_socket_connect
 */
int hss_socket_connect_in4(int socket_id, char *ip_addr, int ip_len,
	__be16 port, int flags, struct rhashtable *socket_ht)
{
	struct sockaddr_in addr = {0};
	struct hss_host_socket *socket;
	int ret = 0;

	socket = hss_get_socket(&socket_id, socket_ht);
	if (!socket) {
		ret = -EEXIST;
		goto exit;
	}

	ret = hss_addr_in4(ip_addr, ip_len, port, &addr);

	if (!ret)
		ret = kernel_connect(socket->sock, (struct sockaddr *)&addr,
			sizeof(struct sockaddr_in), flags);
exit:
	return ret;
}

/**
 * hss_socket_connect_in6 - Connect an existing socket to an INET6 address
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
int hss_socket_connect_in6(int socket_id, char *ip_addr, int ip_len,
	__be16 port, __be32 flow, __u32 scope, int flags,
	struct rhashtable *socket_ht)
{
	struct sockaddr_in6 addr = {0};
	struct hss_host_socket *socket;
	int ret = 0;

	socket = hss_get_socket(&socket_id, socket_ht);
	if (!socket) {
		ret = -EEXIST;
		goto exit;
	}

	ret = hss_addr_in6(ip_addr, ip_len, port, flow, scope,
		&addr);
	if (!ret)
		ret = kernel_connect(socket->sock, (struct sockaddr *)&addr,
			sizeof(struct in6_addr), flags);
exit:
	return ret;
}

/**
 * hss_socket_write - Writes to a socket
 *
 * @socket_id The socket id to connect
 * @buf The buffer to write
 * @len The length in bytes of the buffer
 *
 * Returns: Number of bytes transmitted or an error code.
 */
int hss_socket_write(int socket_id, void *buf, int len,
	struct rhashtable *socket_ht)
{
	struct hss_host_socket *socket;
	int ret = -EEXIST;
	struct msghdr msg;
	struct kvec vec;

	if (!len) {
		ret = 0;
		goto exit;
	}

	socket = hss_get_socket(&socket_id, socket_ht);
	if (socket) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		vec.iov_len = len;
		vec.iov_base = buf;

		ret = kernel_sendmsg(socket->sock, &msg, &vec, len, len);
	}

exit:
	return ret;
}

/**
 * hss_socket_read - Reads from a socket
 *
 * @socket_id The socket id to connect
 * @buf The buffer to write
 * @len The length in bytes of the buffer
 * @flags Flags to pass to kernel_recvmsg
 *
 * Returns: Number of bytes received or an error code.
 */
int hss_socket_read(int socket_id, void *buf, int len, int flags,
	struct rhashtable *socket_ht)
{
	struct hss_host_socket *socket;
	struct msghdr msg = {};
	struct kvec vec;
	int ret = -EEXIST;

	socket = hss_get_socket(&socket_id, socket_ht);
	if (socket) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		vec.iov_len = len;
		vec.iov_base = buf;

		ret = kernel_recvmsg(socket->sock, &msg, &vec, 1, len, 0);
	}
	return ret;
}
