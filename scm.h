/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file scm.h
 * @brief SCM structure definitions
 */
#ifndef SCM_H
#define SCM_H

#include <linux/kernel.h>

enum __attribute__ ((__packed__)) scm_opcode {
	SCM_OP_OPEN	= 0x00,
	SCM_OP_CONNECT	= 0x01,
	SCM_OP_SHUTDOWN	= 0x02,
	SCM_OP_TRANSMIT	= 0x03,
	SCM_OP_ACK	= 0x04,
	SCM_OP_ACKDATA	= 0x05,
	SCM_OP_CLOSE	= 0x06,
	SCM_OP_MAX	= 0xFF
};

enum __attribute__ ((__packed__)) scm_family {
	SCM_FAM_IP	= 0x01,
	SCM_FAM_IP6	= 0x02,
	SCM_FAM_MAX	= 0xFFFF
};

enum __attribute__ ((__packed__)) scm_proto {
	SCM_PROTO_TCP	= 0x01,
	SCM_PROTO_UDP	= 0x02,
	SCM_PROTO_MAX	= 0xFFFF
};

enum __attribute__ ((__packed__)) scm_type {
	SCM_TYPE_STREAM	= 0x01,
	SCM_TYPE_DGRAM	= 0x02,
	SCM_TYPE_MAX	= 0xFF
};

struct scm_packet_hdr {
	enum scm_opcode	opcode;
	__u8		msg_id;
	__u8		sock_id;
	__u8		payload_len;
};

struct scm_payload_data{
	__u32 payloadLen;
	unsigned char data[];
};

struct scm_payload_open {
	enum scm_family	addr_family;
	enum scm_proto	protocol;
	enum scm_type	type;
};


struct scm_payload_ack {
	enum scm_opcode	orig_opcode;
	__u8			rsvd;
	union {
		char	close[0];
		__u8	open;
		__u8	connect;
	};
};

struct scm_payload_connect_ip6 {
	__be32		flow_info;
	__u32		scope_id;
	char		ip_addr[16];
};

struct scm_payload_connect_ip4 {
	__be32		ip_addr;
};

struct scm_payload_connect_ip {
	enum scm_family	family;
	__u8		resvd;
	__be16		port;
	union {
		struct scm_payload_connect_ip6 ip6; 
		struct scm_payload_connect_ip4 ip4;
	};
};

struct scm_packet {
	struct scm_packet_hdr	hdr;
	union {
		unsigned char scm_payload_none[0];
		struct scm_payload_open open;
		struct scm_payload_connect_ip connect;
		struct scm_payload_ack ack;
	};
};
#endif