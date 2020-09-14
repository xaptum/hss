/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file hss-ring.h
 * @brief HSS ring function defs
 */
#ifndef XAPRC00X_RING_H
#define XAPRC00X_RING_H

#include <linux/circ_buf.h>

struct hss_ring_section {
	int start;
	int len;
	int wrap;
};

int hss_ring_write(
	struct circ_buf *ring,
	int buf_len, char *buf,
	int len);
struct hss_ring_section hss_consumer_section(
	struct circ_buf *ring, int buf_len, int len);
void hss_ring_consume(
	struct circ_buf *ring, int buf_size, struct hss_ring_section section);

#endif
