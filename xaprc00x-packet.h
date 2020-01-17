/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file scm.h
 * @brief SCM structure definitions
 */
#ifndef SCM_PACKET_H
#define SCM_PACKET_H

#include "scm.h"

struct scm_packet *xaprc00x_new_packet(int opcode, int sock_id,
	int max_payload_len);
void xaprc00x_packet_fill_close(struct scm_packet * packet, int sock_id);
void xaprc00x_fill_payload(struct scm_packet *packet, void *buf, size_t len);
void xaprc00x_packet_fill_transmit(struct scm_packet *packet, int sock_id,
	void *buf, size_t len);
void xaprc00x_fill_packet(struct scm_packet * packet, int opcode,
	int sock_id);

void xaprc00x_packet_fill_ack(struct scm_packet_hdr *orig,
	struct scm_packet *ack);
void xaprc00x_packet_fill_ack_open(struct scm_packet *packet,
	struct scm_packet *ack, int ret, int id);
void xaprc00x_packet_fill_ack_connect(struct scm_packet *packet,
	struct scm_packet *ack, int ret);
#endif