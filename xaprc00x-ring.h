/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file xaprc00x-ring.h
 * @brief SCM ring function defs
 */
#ifndef XAPRC00X_RING_H
#define XAPRC00X_RING_H

#include <linux/circ_buf.h>

struct xaprc00x_ring_section {
	int start;
	int len;
	int wrap;
};

int xaprc00x_ring_write(
	struct circ_buf *ring,
	int buf_len, char *buf,
	int len);
struct xaprc00x_ring_section xaprc00x_consumer_section(
	struct circ_buf *ring, int buf_len, int len);
void xaprc00x_ring_consume(
	struct circ_buf *ring, int buf_size, struct xaprc00x_ring_section section);

#endif
