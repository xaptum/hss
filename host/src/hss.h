/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file hss.h
 * @brief HSS structure definitions
 */
#ifndef HSS_H
#define HSS_H

#include <linux/kernel.h>
#include <linux/slab.h>

/* Define the length of fixed data on each packet type. Useful for knowing where
 * to write arbitrary payloads. All values are taken from section 3.3.5 of the
 * HSS specification. These values should never be used for memory operations on
 * struct hss_packet. */
#define HSS_HDR_LEN 12
#define HSS_FIXED_LEN_CLOSE HSS_HDR_LEN
#define HSS_FIXED_LEN_TRANSMIT HSS_HDR_LEN
#define HSS_FIXED_LEN_ACK HSS_HDR_LEN+3
#define HSS_FIXED_LEN_REPLY HSS_FIXED_LEN_ACK

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

    out->handle = open->handle;
    out->protocol = open->protocol;
    out->addr_family = open->addr_family;
    out->type = open->type;
    return open;
}

/**
 * _hss_packet_to_buf - Convert fixed packet fields to buffer
 *
 * @dst The buffer to write to
 * @src The packet field to read from
 * @offset The buffer offset to write to (will be incremented)
 * @conv_end Whether to convert endianness to little-endian
 *
 * Converts fixed fields whos width are known at compile time
 * from the packet to the buf. For use by hss_packet_to_buf
 *
 * Return: None
 */
#define _hss_packet_to_buf(dst,src,offset,conv_end)			\
	do {								\
		char *_src = (char *)src;				\
		__le16 _src16;						\
		__le32 _src32;						\
		__le64 _src64;						\
		if (conv_end && sizeof(*src) == 2) {			\
			_src16 = cpu_to_le16(*src);			\
			_src = (char *) &_src16;			\
		} else if (conv_end && sizeof(*src) == 4) {		\
			_src32 = cpu_to_le32(*src);			\
			_src = (char *) &_src32;			\
		} else if (conv_end && sizeof(*src) == 8) {		\
			_src64 = cpu_to_le64(*src);			\
			_src = (char *) &_src64;			\
		}							\
		memcpy(((char*)dst) + offset, _src, sizeof(*src));	\
		offset += sizeof(*src);					\
	} while (0)

/**
 * _hss_packet_from_buf - Extract fixed fields from buffer into packet
 *
 * @src The buffer to read from
 * @src The packet field to write to
 * @cnt The buffer offset to read from (will be incremented)
 * @conv_end Whether to convert endianness from little-endian
 *
 * Converts fixed fields whos width are known at compile time
 * from the buffer to the packet struct. For use by hss_packet_from_buf
 *
 * Return: None
 */
#define _hss_packet_from_buf(src,dst,offset,conv_end)			\
	do {								\
		memcpy(dst, ((char*)src) + offset, sizeof(*dst));	\
		offset += sizeof(*dst);					\
		if (conv_end && sizeof(*dst) == 2)			\
			*dst = le16_to_cpu(*dst);			\
		if (conv_end && sizeof(*dst) == 4)			\
			*dst = le32_to_cpu(*dst);			\
		if (conv_end && sizeof(*dst) == 8)			\
			*dst = le64_to_cpu(*dst);			\
	} while (0)

/**
 * hss_packet_##dir##_buf - Serially steps through an HSS packet performing the descired operation
 *
 * @pkt An alligned HSS packet
 * @buf An unalligned buffer for transmission
 * @payload_fields Whether to copy fixed payload fields or just the header
 *
 * Goes field by field through the packet structure either reading from or writing to the field.
 * The other target is an unalligned HSS buffer that is has either been received or is about to be sent
 * over USB.
 *
 * Return: The number of bytes operated upon in the buffer.
 */
#define HSS_COPY_FIELDS 1
#define HSS_COPY_HDR 0
#define _CREATE_HSS_PACKET_DIR(dir) \
	static inline size_t hss_packet_##dir##_buf(struct hss_packet *pkt, char *buf, int payload_fields) \
	{ \
		size_t cnt = 0; \
 \
		_hss_packet_##dir##_buf(buf, &pkt->hdr.opcode, cnt, 1); \
		_hss_packet_##dir##_buf(buf, &pkt->hdr.msg_id, cnt, 1); \
		_hss_packet_##dir##_buf(buf, &pkt->hdr.sock_id, cnt, 1); \
		_hss_packet_##dir##_buf(buf, &pkt->hdr.payload_len, cnt, 1); \
 \
		if (payload_fields) { \
			switch (pkt->hdr.opcode) { \
				case HSS_OP_OPEN: \
					_hss_packet_##dir##_buf(buf, &pkt->open.handle, cnt, 1); \
					_hss_packet_##dir##_buf(buf, &pkt->open.addr_family, cnt, 1); \
					_hss_packet_##dir##_buf(buf, &pkt->open.protocol, cnt, 1); \
					_hss_packet_##dir##_buf(buf, &pkt->open.type, cnt, 1); \
					break; \
				case HSS_OP_CONNECT: \
						_hss_packet_##dir##_buf(buf, &pkt->connect.family, cnt, 1); \
						_hss_packet_##dir##_buf(buf, &pkt->connect.port, cnt, 1); \
						if (pkt->connect.family == HSS_FAM_IP) \
							_hss_packet_##dir##_buf(buf, &pkt->connect.addr.ip4.ip_addr, cnt, 0); \
						else if (pkt->connect.family == HSS_FAM_IP6) { \
							_hss_packet_##dir##_buf(buf, &pkt->connect.addr.ip6.flow_info, cnt, 0); \
							_hss_packet_##dir##_buf(buf, &pkt->connect.addr.ip6.scope_id, cnt, 0); \
							_hss_packet_##dir##_buf(buf, pkt->connect.addr.ip6.ip_addr, cnt, 0); \
						} \
					break; \
				case HSS_OP_ACK: \
					_hss_packet_##dir##_buf(buf, &pkt->ack.orig_opcode, cnt, 1); \
					_hss_packet_##dir##_buf(buf, &pkt->ack.code, cnt, 1); \
					break; \
				case HSS_OP_ACKDATA: \
				case HSS_OP_CLOSE: \
				case HSS_OP_TRANSMIT: \
				case HSS_OP_SHUTDOWN: \
				default: \
					break; \
			} \
		} \
		return cnt; \
	}
_CREATE_HSS_PACKET_DIR(to); /* hss_packet_to_buf */
_CREATE_HSS_PACKET_DIR(from); /* hss_packet_from_buf */
#endif
