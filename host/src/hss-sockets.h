/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file hss_sockets.h
 * @brief External functions for the HSS host socket manager.
 */
#ifndef __XAPRC00X_SOCKETS_H
#define __XAPRC00X_SOCKETS_H

int hss_socket_mgr_init(struct rhashtable **table);

void hss_socket_mgr_destroy(struct rhashtable *socket_hash_table);

int hss_socket_create(int socket_id, unsigned short int family, int type,
	int protocol, struct rhashtable *socket_hash_table);

void hss_socket_close(int socket_id,
	struct rhashtable *socket_hash_table);

void hss_socket_shutdown(int socket_id, int dir,
	struct rhashtable *socket_hash_table);

int hss_socket_connect_in4(int socket_id, char *addr, int addrlen,
	__be16 port, int flags, struct rhashtable *socket_hash_table);

int hss_socket_connect_in6(int socket_id, char *addr, int addrlen,
	__be16 port, __be32 flow, __u32 scope, int flags,
	struct rhashtable *socket_hash_table);

int hss_socket_write(int socket_id, void *const buf, int len,
	struct rhashtable *socket_hash_table);

int hss_socket_read(int socket_id, void *buf, int size, int flags,
	struct rhashtable *socket_hash_table);

int hss_socket_exists(int key, struct rhashtable *socket_hash_table);

#endif /* __XAPRC00X_SOCKETS_H */
