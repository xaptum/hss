// SPDX-License-Identifier: GPL-2.0+
/**
 * @file xaprc00x_proxy.c
 * @brief Implementation of the host proxy for SCM. These functions
 *	are called by the USB system when a message is completed.
 */

#include <linux/socket.h>
#include <linux/net.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include "scm.h"
#include "xaprc00x-proxy.h"
#include "xaprc00x-sockets.h"
#include "xaprc00x-usb.h"

static int get_proxy_socket_id(__u16 dev, __u8 sock_id)
{
	return (dev<<8) | sock_id;
}

static __u8 get_device_socket_id(int sock_id)
{
	return sock_id & 0xFF;
}

struct work_data_t {
	struct work_struct work;
	int packet_len;
	u16 dev;
	void *context; /* Data to pass back to USB functions */
	unsigned char data[];
};

struct workqueue_struct *xaprc00x_proxy_init(int dev, void *context)
{
	int ret;
	char name[11];
	struct workqueue_struct *wq = NULL;

	if (dev < 0 || dev > 255) {
		goto exit;
	}

	/* Name and allocate the workqueue */
	sprintf(name,"scm_wq_%d",dev);
	wq = create_workqueue(name);
	if (!wq) {
		goto exit;
	}

	/* Initialize the proxy */
	ret = xaprc00x_socket_mgr_init();

	if (ret) {
		destroy_workqueue(wq);
		wq = NULL;
	}
exit:
	return wq;
}

void xaprc00x_proxy_destroy(struct workqueue_struct *wq)
{
	destroy_workqueue(wq);
	xaprc00x_socket_mgr_destroy();
}

/**
 * xaprc00x_proxy_fill_ack_common - Fill common ACK fields
 *
 * @orig The header of the packet being responded to
 * @ack The ACK packet to populate
 *
 * Fills common fields common to all ACK transactions that can be known by
 * reading the original message header.
 */
static void xaprc00x_proxy_fill_ack_common(struct scm_packet_hdr *orig,
	struct scm_packet *ack)
{
	ack->hdr.opcode = SCM_OP_ACK;
	ack->hdr.msg_id = orig->msg_id;
	ack->hdr.payload_len = 0;
	ack->hdr.sock_id = orig->sock_id;
	ack->ack.orig_opcode = orig->opcode;
}

/**
 * xaprc00x_proxy_fill_ack_open - Fill open specific ACK
 *
 * @packet The packet being reponded to
 * @ack The ACK packet to populate
 * @ret The return code from the operation
 * @id The ID created by the operation
 *
 * Fills an ACK packet after an OPEN procedure. ID is ignored unless ret==0
 */
static void xaprc00x_proxy_fill_ack_open(struct scm_packet *packet,
	struct scm_packet *ack, int ret, u8 id)
{
	xaprc00x_proxy_fill_ack_common(&packet->hdr, ack);
	ack->hdr.payload_len = 1;
	switch (ret) {
	case 0:
		ack->ack.open.code = SCM_E_SUCCESS;
		ack->ack.open.sock_id = id;
		break;
	case -EINVAL:
		ack->ack.open.code = SCM_E_INVAL;
		break;
	default:
		ack->ack.open.code = SCM_E_HOSTERR;
		break;
	}
	ack->ack.connect = ret;
}

/**
 * xaprc00x_proxy_fill_ack_connect - Fill connect specific ACK
 *
 * @packet The packet being reponded to
 * @ack The ACK packet to populate
 * @ret The return code from the operation
 *
 * Fills an ACK packet after an CONNECT procedure.
 */
static void xaprc00x_proxy_fill_ack_connect(struct scm_packet *packet,
	struct scm_packet *ack, int ret)
{
	xaprc00x_proxy_fill_ack_common(&packet->hdr, ack);
	ack->hdr.payload_len = 1;
	switch (ret) {
	case 0:
		ack->ack.connect = SCM_E_SUCCESS;
		break;
	case -ECONNREFUSED:
		ack->ack.connect = SCM_E_CONNREFUSED;
		break;
	case -ENETUNREACH:
		ack->ack.connect = SCM_E_NETUNREACH;
		break;
	case -ETIMEDOUT:
		ack->ack.connect = SCM_E_TIMEDOUT;
		break;
	default:
		ack->ack.connect = SCM_E_HOSTERR;
		break;
	}
}

static int xaprc00x_family_to_host(enum scm_family dev_fam)
{
	int host_fam = -1;
	if (dev_fam == SCM_FAM_IP) {
		host_fam = PF_INET;
	} else if (dev_fam == SCM_FAM_IP6) {
		host_fam = PF_INET6;
	}
	return host_fam;
}

static enum scm_proto xaprc00x_protocol_to_host(enum scm_proto dev_proto)
{
	int host_proto = -1;

	if (dev_proto == SCM_PROTO_TCP) {
		host_proto = IPPROTO_TCP;
	} else if (dev_proto == SCM_PROTO_UDP) {
		host_proto = IPPROTO_UDP;
	}
	return host_proto;
}

static enum scm_type xaprc00x_type_to_host(enum scm_type dev_type)
{
	int host_type = -1;
	if (dev_type == SCM_TYPE_STREAM) {
		host_type = SOCK_STREAM;
	} else if (dev_type == SCM_TYPE_DGRAM) {
		host_type = SOCK_DGRAM;
	}
	return host_type;
}

/**
 * xaprc00x_proxy_process_open - Process an OPEN packet
 *
 * @packet The packet sent by the device
 * @dev The device ID requesting this operation
 * @ack The ACK packet to populate
 *
 * Performs an OPEN operation based on an incoming SCM packet.
 */
void xaprc00x_proxy_process_open(struct scm_packet *packet, u16 dev,
	struct scm_packet **ack)
{

	int ret;
	int family, type, protocol;
	struct scm_payload_open *payload;
	int sock_id;

	/* Seperate the socket ID out of the device ID */
	sock_id = get_proxy_socket_id(dev,0);

	/* Find the smallest unoccupied ID for this device */
	while (xaprc00x_socket_exists(sock_id))
		sock_id++;

	 payload = &packet->open;

	/* Translate the SCM parameters to ones the socket interface */
	family = xaprc00x_family_to_host(payload->addr_family);
	if (family < 0) {
		ret = -EINVAL;
		goto fill_ack;
	}

	protocol = xaprc00x_protocol_to_host(payload->protocol);
	if (xaprc00x_protocol_to_host < 0) {
		ret = -EINVAL;
		goto fill_ack;
	}

	type = xaprc00x_type_to_host(payload->type);
	if (type < 0) {
		ret = -EINVAL;
		goto fill_ack;
	}

	ret = xaprc00x_socket_create(sock_id, family, type, protocol);

fill_ack:
	/* If creation succeded return created ID without the device */
	*ack = kmalloc(sizeof(struct scm_packet), GFP_KERNEL);
	xaprc00x_proxy_fill_ack_open(packet, *ack, ret, get_device_socket_id(sock_id));
}

/**
 * xaprc00x_proxy_process_connect - Process an CONNECT packet
 *
 * @packet The packet sent by the device
 * @dev The device ID requesting this operation
 * @ack The ACK packet to populate
 *
 * Performs an CONNECT operation based on an incoming SCM packet.
 */
void xaprc00x_proxy_process_connect(struct scm_packet *packet, u16 dev,
	struct scm_packet **ack)
{
	int ret;
	struct scm_payload_connect_ip *payload = &packet->connect;
	struct scm_packet_hdr *hdr = &packet->hdr;
	int id = get_proxy_socket_id(dev, hdr->sock_id);

	switch (payload->family) {
	case SCM_FAM_IP:
		ret = xaprc00x_socket_connect_in4(id, 
			(char *)&(payload->addr.ip4.ip_addr), 4, payload->port, 0);
		break;
	case SCM_FAM_IP6:
		ret = xaprc00x_socket_connect_in6(id, 
			(char *)&(payload->addr.ip6.ip_addr), 16, payload->port,
			payload->addr.ip6.flow_info, payload->addr.ip6.scope_id, 0);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	*ack = kmalloc(sizeof(struct scm_packet), GFP_KERNEL);
	xaprc00x_proxy_fill_ack_connect(packet, *ack, ret);
}

/**
 * xaprc00x_proxy_process_close - Process an CLOSE packet
 *
 * @packet The packet sent by the device
 * @dev The device ID requesting this operation
 * @ack The ACK packet to populate
 *
 * Performs an CLOSE operation based on an incoming SCM packet.
 */
void xaprc00x_proxy_process_close(struct scm_packet *packet, u16 dev,
	struct scm_packet **ack)
{
	struct scm_packet_hdr *hdr = &packet->hdr;
	int id = get_proxy_socket_id(dev, hdr->sock_id);

	xaprc00x_socket_close(id);

	/* Close ACKs do not contain status data. */
	*ack = kmalloc(sizeof(struct scm_packet), GFP_KERNEL);
	xaprc00x_proxy_fill_ack_common(hdr,*ack);
}

/* Can be called in an atomic context */
void xaprc00x_proxy_rcv_cmd(struct workqueue_struct *wq,
	struct scm_packet *packet, int packet_len, u16 dev, void *context)
{
	struct work_data_t *newwork;

	newwork = kmalloc(sizeof(struct work_data_t)+packet_len, GFP_ATOMIC);

	newwork->context = context;
	newwork->dev = dev;

	newwork->packet_len = packet_len;
	memcpy(newwork->data,packet,packet_len);
	INIT_WORK(&newwork->work, xaprc00x_proxy_process_cmd);
	queue_work(wq,&newwork->work);
}

/**
 * xaprc00x_proxy_process_cmd - Process a command from USB
 *
 * @scm_packet The packet being processed
 * @len The length of the data being passed
 * @ack The ack structure to fill out on complete.
 *
 * Acts as an intermediary between USB and the socket interface. Ack will be
 * ignored if the command type does not reply (such as recieving an ACK).
 */
void xaprc00x_proxy_process_cmd(struct work_struct *work)
{
	struct work_data_t *work_data;
	struct scm_packet *ack = NULL;
	struct scm_packet *packet;
	int packet_len;
	int dev;

	work_data = (struct work_data_t*)work;
	packet = (struct scm_packet *)&work_data->data;
	packet_len = work_data->packet_len;
	dev = work_data->dev;

	/* Sanity check the length against the packet definition */
	if (packet->hdr.payload_len+sizeof(struct scm_packet_hdr) > packet_len) {
		return;
	}

	switch (packet->hdr.opcode) {
	case SCM_OP_OPEN:
		xaprc00x_proxy_process_open(packet, dev, &ack);
		break;
	case SCM_OP_CONNECT:
		xaprc00x_proxy_process_connect(packet, dev, &ack);
		break;
	case SCM_OP_CLOSE:
		xaprc00x_proxy_process_close(packet, dev, &ack);
		break;
	case SCM_OP_SHUTDOWN:
	case SCM_OP_TRANSMIT:
	case SCM_OP_ACK:
	case SCM_OP_ACKDATA:
	default:
		break;
	}

	if (ack) {
		xaprc00x_cmd_out(work_data->context, ack,
			sizeof(*ack)+ack->hdr.payload_len);
	}
}
