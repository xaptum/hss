/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file hss.h
 * @brief HSS structure definitions
 */
#ifndef HSS_H
#define HSS_H

#include <linux/kernel.h>

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
#endif
