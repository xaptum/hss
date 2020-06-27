/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file hss.h
 * @brief HSS structure definitions
 */
#ifndef HSS_PACKET_H
#define HSS_PACKET_H

#include <linux/kernel.h>
#include "hss.h"

int hss_get_packet_len(struct hss_packet *packet);

struct hss_packet *hss_new_packet(int opcode, int sock_id,
	int max_payload_len);
void hss_packet_fill_close(struct hss_packet *packet, u32 sock_id);
void hss_fill_payload(struct hss_packet *packet, void *buf, u32 len);
void hss_packet_fill_transmit(struct hss_packet *packet, int sock_id,
	void *buf, size_t len);
void hss_fill_packet(struct hss_packet *packet, u16 opcode,
	u32 sock_id);
void hss_packet_fill_noop(struct hss_packet *packet, int len);

void hss_packet_fill_ack(struct hss_packet_hdr *orig,
	struct hss_packet *ack);
void hss_packet_fill_ack_open(struct hss_packet *packet,
	struct hss_packet *ack, int ret, u32 id);
void hss_packet_fill_ack_connect(struct hss_packet *packet,
	struct hss_packet *ack, int ret);

struct hss_payload_open *hss_get_payload_open(struct hss_packet *packet, struct hss_payload_open *out);
struct hss_payload_connect_ip *hss_get_payload_connect(struct hss_packet *packet, struct hss_payload_connect_ip *out);
struct hss_packet_hdr *hss_get_header(struct hss_packet *packet, struct hss_packet_hdr *out);
#endif
