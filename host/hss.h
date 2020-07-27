/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file hss.h
 * @brief HSS structure definitions
 */
#ifndef HSS_H
#define HSS_H

#include <linux/kernel.h>
#include <linux/slab.h>

enum __attribute__ ((__packed__)) hss_opcode {
	HSS_OP_OPEN	= 0x00,
	HSS_OP_CONNECT	= 0x01,
	HSS_OP_SHUTDOWN	= 0x02,
	HSS_OP_TRANSMIT	= 0x03,
	HSS_OP_ACK	= 0x04,
	HSS_OP_ACKDATA	= 0x05,
	HSS_OP_CLOSE	= 0x06,
	HSS_OP_MAX	= 0xFFFF
};

enum __attribute__ ((__packed__)) hss_family {
	HSS_FAM_IP	= 0x01,
	HSS_FAM_IP6	= 0x02,
	HSS_FAM_MAX	= 0xFFFF
};

enum __attribute__ ((__packed__)) hss_proto {
	HSS_PROTO_TCP	= 0x01,
	HSS_PROTO_UDP	= 0x02,
	HSS_PROTO_MAX	= 0xFFFF
};

enum __attribute__ ((__packed__)) hss_type {
	HSS_TYPE_STREAM	= 0x01,
	HSS_TYPE_DGRAM	= 0x02,
	HSS_TYPE_MAX	= 0xFF
};

enum __attribute__ ((__packed__)) hss_error {
	HSS_E_SUCCESS		= 0x00,
	HSS_E_HOSTERR		= 0x01,
	HSS_E_INVAL		= 0x02,
	HSS_E_CONNREFUSED	= 0x03,
	HSS_E_PROTONOSUPPORT	= 0x04,
	HSS_E_NETUNREACH	= 0x05,
	HSS_E_TIMEDOUT		= 0x06,
	HSS_E_MISMATCH		= 0x07,
	HSS_E_NOTCONN		= 0x08,
	HSS_E_MAX		= 0xFF
};

struct hss_packet_hdr {
	enum hss_opcode	opcode;
	__le16		msg_id;
	__le32		sock_id;
	__le32		payload_len;
};

struct hss_payload_data {
	__u32 payloadLen;
	unsigned char data[];
};

struct hss_payload_open {
	__le32		handle;
	enum hss_family	addr_family;
	enum hss_proto	protocol;
	enum hss_type	type;
};

struct hss_payload_ack {
	enum hss_opcode		orig_opcode;
	enum hss_error		code;
	union {
		char	empty[0];
	};
};

struct hss_payload_connect_ip6 {
	__le32		flow_info;
	__le32		scope_id;
	char		ip_addr[16];
};

struct hss_payload_connect_ip4 {
	__be32		ip_addr;
};

union hss_payload_connect_ip_addr {
	struct hss_payload_connect_ip6 ip6;
	struct hss_payload_connect_ip4 ip4;
};

struct hss_payload_connect_ip {
	enum hss_family	family;
	__u8                                    resvd;
	__le16					port;
	union hss_payload_connect_ip_addr	addr;
};

struct hss_packet {
	struct hss_packet_hdr	hdr;
	union {
		unsigned char hss_payload_none[0];
		struct hss_payload_open open;
		struct hss_payload_connect_ip connect;
		struct hss_payload_ack ack;
	};
};


/* Adds a CPU ordered u32 a little endian unisgned integer */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define add_cpu_to_le(baseLE, addCPU)  baseLE = cpu_to_le32(le32_to_cpu(baseLE) + addCPU)
#else
#define add_cpu_to_le(baseLE, addCPU)  baseLE = baseLE + addCPU
#endif

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
static inline int hss_get_packet_len(struct hss_packet *packet)
{
	return sizeof(struct hss_packet_hdr) + packet->hdr.payload_len;
}

static inline void hss_fill_packet(struct hss_packet *packet, u16 opcode,
	u32 sock_id, u16 msg_id)
{
	packet->hdr.msg_id = cpu_to_le16(msg_id);
	packet->hdr.opcode = cpu_to_le16(opcode);
	packet->hdr.sock_id = cpu_to_le32(sock_id);
}

static inline struct hss_packet *hss_new_packet(int opcode, int sock_id,
	int max_payload_len, u16 msg_id)
{
	struct hss_packet *packet = kzalloc(sizeof(*packet) + max_payload_len,
		GFP_KERNEL);
	hss_fill_packet(packet, opcode, sock_id, msg_id);
	return packet;
}

static inline void hss_fill_payload(struct hss_packet *packet, void *buf, u32 len)
{
	packet->hdr.payload_len = cpu_to_le32(len);
	if (buf)
		memcpy(packet->hss_payload_none, buf, len);
}

static inline void hss_packet_fill_close(struct hss_packet *packet, uint32_t sock_id, u16 msg_id)
{
	hss_fill_packet(packet, HSS_OP_CLOSE, sock_id, msg_id);
}

static inline void hss_packet_fill_transmit(struct hss_packet *packet, int sock_id,
	void *buf, size_t len, u16 msg_id)
{
	hss_fill_packet(packet, HSS_OP_TRANSMIT, sock_id, msg_id);
	hss_fill_payload(packet, buf, len);
}

static inline void hss_packet_fill_noop(struct hss_packet *packet, int len, u16 msg_id)
{
	hss_fill_packet(packet, HSS_OP_MAX, 0, msg_id);
	hss_fill_payload(packet, NULL, len);
}

/**
 * hss_packet_fill_ack - Fill common ACK fields
 *
 * @orig The header of the packet being responded to
 * @ack The ACK packet to populate
 *
 * Fills common fields common to all ACK transactions that can be known by
 * reading the original message header.
 */
static inline void hss_packet_fill_ack(struct hss_packet_hdr *orig,
	struct hss_packet *ack)
{
	ack->hdr.opcode = cpu_to_le16(HSS_OP_ACK);
	ack->hdr.msg_id = cpu_to_le16(orig->msg_id);
    ack->hdr.sock_id = cpu_to_le32(orig->sock_id);
	ack->hdr.payload_len = cpu_to_le32(3);
	ack->ack.orig_opcode = cpu_to_le16(orig->opcode);
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
static inline void hss_packet_fill_ack_open(struct hss_packet *packet,
	struct hss_packet *ack, int ret, u32 id)
{
	hss_packet_fill_ack(&packet->hdr, ack);
	add_cpu_to_le(ack->hdr.payload_len, sizeof(ack->ack.empty));
	ack->hdr.sock_id = cpu_to_le32(id);
	switch (ret) {
	case 0:
		ack->ack.code = HSS_E_SUCCESS;
		break;
	case -EINVAL:
		ack->ack.code = HSS_E_INVAL;
		break;
	default:
		ack->ack.code = HSS_E_HOSTERR;
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
static inline void hss_packet_fill_ack_connect(struct hss_packet *packet,
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

static inline struct hss_packet_hdr *hss_get_header(struct hss_packet *packet, struct hss_packet_hdr *out) {
    struct hss_packet_hdr *hdr = &packet->hdr;

    out->opcode = le16_to_cpu(hdr->opcode);
    out->msg_id = le16_to_cpu(hdr->msg_id);
    out->sock_id = le32_to_cpu(hdr->sock_id);
    out->payload_len = le32_to_cpu(hdr->payload_len);

    return hdr;
}

static inline struct hss_payload_connect_ip *hss_get_payload_connect(struct hss_packet *packet, struct hss_payload_connect_ip *out)
{
    struct hss_payload_connect_ip *connect = &packet->connect;

    out->family = le16_to_cpu(connect->family);
    out->port = le16_to_cpu(connect->port);

    /* Note: All address fields are passed in network byte order */
    memcpy(&out->addr, &connect->addr,
        out->family==HSS_FAM_IP6 ? sizeof(struct hss_payload_connect_ip6) : sizeof(struct hss_payload_connect_ip4));

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
static inline struct hss_payload_open *hss_get_payload_open(struct hss_packet *packet, struct hss_payload_open *out)
{
    struct hss_payload_open *open = &packet->open;

    out->handle = le32_to_cpu(open->handle);
    out->protocol = le16_to_cpu(open->protocol);
    out->addr_family = le16_to_cpu(open->addr_family);
    out->type = open->type;
    return open;
}
#endif
