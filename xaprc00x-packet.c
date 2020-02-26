// SPDX-License-Identifier: GPL-2.0+
/**
 * @file xaprc00x-packet.c
 * @brief Implementation of various packet related processes.
 */

#include <linux/string.h>
#include <linux/slab.h>
#include "scm.h"
#include "xaprc00x-packet.h"


static atomic_t g_msg_id;


/**
 * xaprc00x_get_packet_len - Returns the full length of the scm packet,
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
int xaprc00x_get_packet_len(struct scm_packet *packet)
{
	return sizeof(struct scm_packet_hdr) + packet->hdr.payload_len;
}

struct scm_packet *xaprc00x_new_packet(int opcode, int sock_id,
	int max_payload_len)
{
	struct scm_packet *packet = kzalloc(sizeof(*packet) + max_payload_len,
		GFP_KERNEL);
	xaprc00x_fill_packet(packet, opcode, sock_id);
	return packet;
}

void xaprc00x_fill_packet(struct scm_packet *packet, int opcode,
	int sock_id)
{
	packet->hdr.msg_id = atomic_inc_return(&g_msg_id);
	packet->hdr.opcode = opcode;
	packet->hdr.sock_id = sock_id;
}

void xaprc00x_fill_payload(struct scm_packet *packet, void *buf, size_t len)
{
	packet->hdr.payload_len = len;
	if (buf)
		memcpy(packet->scm_payload_none, buf, len);
}

void xaprc00x_packet_fill_close(struct scm_packet *packet, int sock_id)
{
	xaprc00x_fill_packet(packet, SCM_OP_CLOSE, sock_id);
}

void xaprc00x_packet_fill_transmit(struct scm_packet *packet, int sock_id,
	void *buf, size_t len)
{
	xaprc00x_fill_packet(packet, SCM_OP_TRANSMIT, sock_id);
	xaprc00x_fill_payload(packet, buf, len);
}

void xaprc00x_packet_fill_noop(struct scm_packet *packet, int len)
{
	xaprc00x_fill_packet(packet, SCM_OP_MAX, 0);
	xaprc00x_fill_payload(packet, NULL, len);
}

/**
 * xaprc00x_packet_fill_ack - Fill common ACK fields
 *
 * @orig The header of the packet being responded to
 * @ack The ACK packet to populate
 *
 * Fills common fields common to all ACK transactions that can be known by
 * reading the original message header.
 */
void xaprc00x_packet_fill_ack(struct scm_packet_hdr *orig,
	struct scm_packet *ack)
{
	ack->hdr.opcode = SCM_OP_ACK;
	ack->hdr.msg_id = orig->msg_id;
	ack->hdr.payload_len = 3;
	ack->hdr.sock_id = orig->sock_id;
	ack->ack.orig_opcode = orig->opcode;
}

/**
 * xaprc00x_packet_fill_ack_open - Fill open specific ACK
 *
 * @packet The packet being reponded to
 * @ack The ACK packet to populate
 * @ret The return code from the operation
 * @id The ID created by the operation
 *
 * Fills an ACK packet after an OPEN procedure. ID is ignored unless ret==0
 */
void xaprc00x_packet_fill_ack_open(struct scm_packet *packet,
	struct scm_packet *ack, int ret, int id)
{
	xaprc00x_packet_fill_ack(&packet->hdr, ack);
	ack->hdr.payload_len += sizeof(ack->ack.empty);
	switch (ret) {
	case 0:
		ack->ack.code = SCM_E_SUCCESS;
		ack->hdr.sock_id = id;
		break;
	case -EINVAL:
		ack->ack.code = SCM_E_INVAL;
		break;
	default:
		ack->ack.code = SCM_E_HOSTERR;
		break;
	}
}

/**
 * xaprc00x_packet_fill_ack_connect - Fill connect specific ACK
 *
 * @packet The packet being reponded to
 * @ack The ACK packet to populate
 * @ret The return code from the operation
 *
 * Fills an ACK packet after an CONNECT procedure.
 */
void xaprc00x_packet_fill_ack_connect(struct scm_packet *packet,
	struct scm_packet *ack, int ret)
{
	xaprc00x_packet_fill_ack(&packet->hdr, ack);
	switch (ret) {
	case 0:
		ack->ack.code = SCM_E_SUCCESS;
		break;
	case -ECONNREFUSED:
		ack->ack.code = SCM_E_CONNREFUSED;
		break;
	case -ENETUNREACH:
		ack->ack.code = SCM_E_NETUNREACH;
		break;
	case -ETIMEDOUT:
		ack->ack.code = SCM_E_TIMEDOUT;
		break;
	default:
		ack->ack.code = SCM_E_HOSTERR;
		break;
	}
}
