// SPDX-License-Identifier: GPL-2.0+
/**
 * @file hss-packet.c
 * @brief Implementation of various packet related processes.
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include "hss.h"
#include "hss-packet.h"


static atomic_t g_msg_id;


/**
 * hss_get_packet_len - Returns the full length of the hss packet,
 * or 0 if incomplete
 *
 * @packet The packet being examined
 * @max_len The readable length of the buffer
 * @begin A pointer to the beginning of the circular buffer
 * @wrap_len How many bytes of the header were wrapped around
 *
 * This functions allows a caller to hand it a potentially incomplete buffer
 * and returns the read length for the entire packet, or 0 if not enough memory
 * was given.
 */
int hss_get_packet_len(struct hss_packet *packet)
{
	return sizeof(struct hss_packet_hdr) + packet->hdr.payload_len;
}

struct hss_packet *hss_new_packet(int opcode, int sock_id,
	int max_payload_len)
{
	struct hss_packet *packet = kzalloc(sizeof(*packet) + max_payload_len,
		GFP_KERNEL);
	hss_fill_packet(packet, opcode, sock_id);
	return packet;
}

void hss_fill_packet(struct hss_packet *packet, u16 opcode,
	u32 sock_id)
{
	packet->hdr.msg_id = cpu_to_le16(atomic_inc_return(&g_msg_id));
	packet->hdr.opcode = cpu_to_le16(opcode);
	packet->hdr.sock_id = cpu_to_le16(sock_id);
}

void hss_fill_payload(struct hss_packet *packet, void *buf, u32 len)
{
	packet->hdr.payload_len = cpu_to_le16(len);
	if (buf)
		memcpy(packet->hss_payload_none, buf, len);
}

void hss_packet_fill_close(struct hss_packet *packet, uint32_t sock_id)
{
	hss_fill_packet(packet, HSS_OP_CLOSE, sock_id);
}

void hss_packet_fill_transmit(struct hss_packet *packet, int sock_id,
	void *buf, size_t len)
{
	hss_fill_packet(packet, HSS_OP_TRANSMIT, sock_id);
	hss_fill_payload(packet, buf, len);
}

void hss_packet_fill_noop(struct hss_packet *packet, int len)
{
	hss_fill_packet(packet, HSS_OP_MAX, 0);
	hss_fill_payload(packet, NULL, len);
}

/* Adds a CPU ordered u32 a little endian unisgned integer */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define add_cpu_to_le(baseLE, addCPU)  baseLE = cpu_to_le32(le32_to_cpu(baseLE) + addCPU)
#else
#define add_cpu_to_le(baseLE, addCPU)  baseLE = baseLE + addCPU
#endif

/**
 * hss_packet_fill_ack - Fill common ACK fields
 *
 * @orig The header of the packet being responded to
 * @ack The ACK packet to populate
 *
 * Fills common fields common to all ACK transactions that can be known by
 * reading the original message header.
 */
void hss_packet_fill_ack(struct hss_packet_hdr *orig,
	struct hss_packet *ack)
{
	ack->hdr.opcode = cpu_to_le32(HSS_OP_ACK);
	ack->hdr.msg_id = cpu_to_le32(orig->msg_id);
    ack->hdr.sock_id = cpu_to_le32(orig->sock_id);
	ack->hdr.payload_len = cpu_to_le32(3);
	ack->ack.orig_opcode = cpu_to_le32(orig->opcode);
}

/**
 * hss_packet_fill_ack_open - Fill open specific ACK
 *
 * @packet The packet being reponded to
 * @ack The ACK packet to populate
 * @ret The return code from the operation
 * @id The ID created by the operation
 *
 * Fills an ACK packet after an OPEN procedure. ID is ignored unless ret==0
 */
void hss_packet_fill_ack_open(struct hss_packet *packet,
	struct hss_packet *ack, int ret, u32 id)
{
	hss_packet_fill_ack(&packet->hdr, ack);

    add_cpu_to_le(ack->hdr.payload_len, sizeof(ack->ack.empty));
	switch (ret) {
	case 0:
		ack->ack.code = cpu_to_le32(HSS_E_SUCCESS);
		ack->hdr.sock_id = cpu_to_le32(id);
		break;
	case -EINVAL:
		ack->ack.code = cpu_to_le32(HSS_E_INVAL);
		break;
	default:
		ack->ack.code = cpu_to_le32(HSS_E_HOSTERR);
		break;
	}
}

/**
 * hss_packet_fill_ack_connect - Fill connect specific ACK
 *
 * @packet The packet being reponded to
 * @ack The ACK packet to populate
 * @ret The return code from the operation
 *
 * Fills an ACK packet after an CONNECT procedure.
 */
void hss_packet_fill_ack_connect(struct hss_packet *packet,
	struct hss_packet *ack, int ret)
{
	hss_packet_fill_ack(&packet->hdr, ack);
	switch (ret) {
	case 0:
		ack->ack.code = cpu_to_le32(HSS_E_SUCCESS);
		break;
	case -ECONNREFUSED:
		ack->ack.code = cpu_to_le32(HSS_E_CONNREFUSED);
		break;
	case -ENETUNREACH:
		ack->ack.code = cpu_to_le32(HSS_E_NETUNREACH);
		break;
	case -ETIMEDOUT:
		ack->ack.code = cpu_to_le32(HSS_E_TIMEDOUT);
		break;
	default:
		ack->ack.code = cpu_to_le32(HSS_E_HOSTERR);
		break;
	}
}

struct hss_packet_hdr *hss_get_header(struct hss_packet *packet, struct hss_packet_hdr *out) {
    struct hss_packet_hdr *hdr = &packet->hdr;

    out->opcode = le16_to_cpu(hdr->opcode);
    out->msg_id = le16_to_cpu(hdr->msg_id);
    out->sock_id = le32_to_cpu(hdr->sock_id);
    out->payload_len = le32_to_cpu(hdr->payload_len);

    return hdr;
}

struct hss_payload_connect_ip *hss_get_payload_connect(struct hss_packet *packet, struct hss_payload_connect_ip *out)
{
    struct hss_payload_connect_ip *connect = &packet->connect;

    out->family = le16_to_cpu(connect->family);
    out->port = le16_to_cpu(connect->port);

    /* Note: All address fields are passed in network byte order */
    memcpy(&out->addr, &connect->addr,
        out->family == HSS_FAM_IP6 ? sizeof(struct hss_payload_connect_ip6) : sizeof(struct hss_payload_connect_ip4));

    return connect;
}

/**
 * hss_payload_open - Return OPEN payload from HSS packet in system byte order
 *
 * @packet The packet being read
 *
 * Returns the OPEN payload in a packet, converting non-address fields
 * to system byte order before returning.
 *
 * Return: A pointer to the payload section of the packet.
 */
struct hss_payload_open *hss_get_payload_open(struct hss_packet *packet, struct hss_payload_open *out)
{
    struct hss_payload_open *open = &packet->open;

    out->handle = le32_to_cpu(open->handle);
    out->protocol = le16_to_cpu(open->protocol);
    out->addr_family = le16_to_cpu(open->addr_family);
    out->type = open->type;
    return open;
}
