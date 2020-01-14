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

struct xaprc00x_proxy_context {
	u16 proxy_id;
	u32 sock_counter;
	struct workqueue_struct *proxy_wq;
	struct workqueue_struct *proxy_data_wq;
	struct rhashtable *socket_table;
	void *usb_context;
};

struct work_data_t {
	struct work_struct work;
	int packet_len;
	struct xaprc00x_proxy_context *context;
	unsigned char data[];
};

/* Forward declarations */
static void xaprc00x_proxy_process_cmd(struct work_struct *work);
static void xaprc00x_proxy_process_data(struct work_struct *work);


static u16 xaprc00x_dev_counter;

/**
 * xaprc00x_proxy_init - Initializes an instance of the SCM proxy
 * for a SCM USB driver and returns a pointer to the new instance.
 *
 * @context A pointer to the USB context to use on future calls
 *
 * Returns: A pointer to the new proxy instance.
 *
 * Notes:
 * All proxy API functions expect a `context` pointer generated by this
 * function to know which instance to run on.
 */
void *xaprc00x_proxy_init(void *usb_context)
{
	int ret;
	/* Make the name large enough to hold the largest possible value */
	struct xaprc00x_proxy_context *context = NULL;
	char name[sizeof("scm_wq_65536")];
	struct workqueue_struct *wq = NULL;
	struct workqueue_struct *data_wq = NULL;
	int dev = xaprc00x_dev_counter++;

	/* Name and allocate the workqueue */
	sprintf(name, "scm_wq_%d", dev);
	wq = create_workqueue(name);
	if (!wq)
		goto exit;

	sprintf(name, "scm_data_wq_%d", dev);
	data_wq = create_workqueue(name);
	if (!data_wq)
		goto free_wq;

	context = kmalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		goto free_data_wq;

	context->proxy_id = dev;
	context->proxy_wq = wq;
	context->proxy_data_wq = data_wq;
	context->usb_context = usb_context;
	context->sock_counter = 0;

	/* Initialize the proxy */
	ret = xaprc00x_socket_mgr_init(&context->socket_table);
	if (ret)
		goto free_context;

	goto exit;

free_context:
	kfree(context);
	context = NULL;
free_data_wq:
	destroy_workqueue(data_wq);
free_wq:
	destroy_workqueue(wq);
exit:
	return context;
}

void xaprc00x_proxy_destroy(void *context)
{
	struct xaprc00x_proxy_context *proxy = context;

	destroy_workqueue(proxy->proxy_wq);
	xaprc00x_socket_mgr_destroy(proxy->socket_table);
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
	ack->hdr.payload_len = 3;
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
	struct scm_packet *ack, int ret, int id)
{
	xaprc00x_proxy_fill_ack_common(&packet->hdr, ack);
	ack->hdr.payload_len += sizeof(ack->ack.open);
	switch (ret) {
	case 0:
		ack->ack.code = SCM_E_SUCCESS;
		ack->hdr.sock_id = id;
		ack->ack.open.sock_id = id;
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

static int xaprc00x_family_to_host(enum scm_family dev_fam)
{
	int host_fam = -1;

	if (dev_fam == SCM_FAM_IP)
		host_fam = PF_INET;
	else if (dev_fam == SCM_FAM_IP6)
		host_fam = PF_INET6;

	return host_fam;
}

static enum scm_proto xaprc00x_protocol_to_host(enum scm_proto dev_proto)
{
	int host_proto = -1;

	if (dev_proto == SCM_PROTO_TCP)
		host_proto = IPPROTO_TCP;
	else if (dev_proto == SCM_PROTO_UDP)
		host_proto = IPPROTO_UDP;

	return host_proto;
}

static enum scm_type xaprc00x_type_to_host(enum scm_type dev_type)
{
	int host_type = -1;

	if (dev_type == SCM_TYPE_STREAM)
		host_type = SOCK_STREAM;
	else if (dev_type == SCM_TYPE_DGRAM)
		host_type = SOCK_DGRAM;

	return host_type;
}

/**
 * xaprc00x_proxy_process_open - Process an OPEN packet
 *
 * @packet The packet sent by the device
 * @dev The device ID requesting this operation
 * @ack The ACK packet to populate
 *
 */
void xaprc00x_proxy_process_open(struct scm_packet *packet, u16 dev,
	struct scm_packet *ack, struct xaprc00x_proxy_context *context)
{

	int ret;
	int family, type, protocol;
	struct scm_payload_open *payload;

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
	ret = xaprc00x_socket_create(payload->handle, family, type, protocol,
		context->socket_table);

fill_ack:
	/* If creation succeded return created ID without the device */
	xaprc00x_proxy_fill_ack_open(packet, ack, ret, payload->handle);
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
	struct scm_packet *ack, struct xaprc00x_proxy_context *context)
{
	int ret;
	struct scm_payload_connect_ip *payload = &packet->connect;
	struct scm_packet_hdr *hdr = &packet->hdr;
	int id = hdr->sock_id;

	switch (payload->family) {
	case SCM_FAM_IP:
		pr_info("Connecting IPv4");
		ret = xaprc00x_socket_connect_in4(
			id,
			(char *)&(payload->addr.ip4.ip_addr),
			sizeof(payload->addr.ip4.ip_addr),
			payload->port,
			0,
			context->socket_table);
		break;
	case SCM_FAM_IP6:
		pr_info("Connecting IPv6");
		ret = xaprc00x_socket_connect_in6(
			id,
			(char *)&(payload->addr.ip6.ip_addr),
			sizeof(payload->addr.ip6.ip_addr),
			payload->port,
			payload->addr.ip6.flow_info,
			payload->addr.ip6.scope_id,
			0,
			context->socket_table);
		break;
	default:
		pr_info("Connecting inval");
		ret = -EINVAL;
		break;
	}
	xaprc00x_proxy_fill_ack_connect(packet, ack, ret);
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
	struct scm_packet *ack, struct xaprc00x_proxy_context *context)
{
	struct scm_packet_hdr *hdr = &packet->hdr;
	int id = hdr->sock_id;

	xaprc00x_socket_close(id, context->socket_table);

	/* Close ACKs do not contain status data. */
	xaprc00x_proxy_fill_ack_common(hdr, ack);
}

/**
 * xaprc00x_proxy_rcv_cmd - Receives and begins processing an SCM packet
 *
 * @context A pointer to the proxy instance
 * @packet A pointer to the packet to process
 * @packet_len The length of the packet
 *
 * Notes:
 * Packet can be modified or freed after this function returns.
 * This function may be called in an atomic context.
 */
void xaprc00x_proxy_rcv_cmd(struct scm_packet *packet,
	int packet_len, void *context)
{
	struct work_data_t *newwork;
	struct xaprc00x_proxy_context *proxy_ctx =
		(struct xaprc00x_proxy_context *) context;

	newwork = kmalloc(sizeof(struct work_data_t) + packet_len, GFP_ATOMIC);

	newwork->context = proxy_ctx;
	newwork->packet_len = packet_len;

	memcpy(newwork->data, packet, packet_len);
	INIT_WORK(&newwork->work, xaprc00x_proxy_process_cmd);
	queue_work(proxy_ctx->proxy_wq, &newwork->work);
}

/**
 * xaprc00x_proxy_rcv_bulk - Receives and begins processing an SCM packet
 *
 * @context A pointer to the proxy instance
 * @packet A pointer to the packet to process
 * @packet_len The length of the packet
 *
 * Notes:
 * Packet can be modified or freed after this function returns.
 * This function may be called in an atomic context.
 */
void xaprc00x_proxy_rcv_data(struct scm_packet *packet,
	int packet_len, void *context)
{
	struct work_data_t *newwork;
	struct xaprc00x_proxy_context *proxy_ctx =
		(struct xaprc00x_proxy_context *) context;

	newwork = kmalloc(sizeof(struct work_data_t) + packet_len, GFP_ATOMIC);

	newwork->context = proxy_ctx;
	newwork->packet_len = packet_len;

	memcpy(newwork->data, packet, packet_len);
	INIT_WORK(&newwork->work, xaprc00x_proxy_process_data);
	queue_work(proxy_ctx->proxy_data_wq, &newwork->work);
}


/**
 * xaprc00x_proxy_run_host_cmd -
 * Helper function for xaprc00x_proxy_process_cmd
 *
 * @packet The packet to process
 * @ack The ACK packet to reply with
 * @proxy_context The proxy context
 *
 * Returns: A buffer containing an ACK message or NULL if no ACK.
 *
 * Notes:
 * Any returned ACK buffer is owned by the USB driver and should not be freed
 * or used outside xaprc00x_proxy_process_cmd.
 */
static struct scm_packet *xaprc00x_proxy_run_host_cmd(
	struct scm_packet *packet,
	struct xaprc00x_proxy_context *context)
{
	int dev = context->proxy_id;
	struct scm_packet *ack =
		xaprc00x_get_ack_buf(context->usb_context);

	switch (packet->hdr.opcode) {
	case SCM_OP_OPEN:
		xaprc00x_proxy_process_open(packet, dev, ack, context);
		break;
	case SCM_OP_CONNECT:
		xaprc00x_proxy_process_connect(packet, dev, ack, context);
		break;
	case SCM_OP_CLOSE:
		xaprc00x_proxy_process_close(packet, dev, ack, context);
		break;
	/* No outgoing ACK for incoming ACK or unimplemented */
	case SCM_OP_ACK:
	case SCM_OP_ACKDATA:
	case SCM_OP_SHUTDOWN:
	case SCM_OP_TRANSMIT:
	default:
		ack = NULL;
		break;
	}
	return ack;
}

/**
 * xaprc00x_proxy_process_cmd - Bottom half of xaprc00x_proxy_rcv_cmd
 *
 * @work Work item to process
 *
 * Notes:
 * Work struct is expected to be of type work_data_t and be tailed with
 * `work->packet_len` bytes for the actual packet.
 */
static void xaprc00x_proxy_process_cmd(struct work_struct *work)
{
	struct work_data_t *work_data;
	struct xaprc00x_proxy_context *proxy_context;
	struct scm_packet *packet;
	int packet_len;
	struct scm_packet *ack;
	int expected_packet_len;

	work_data = (struct work_data_t *) work;
	proxy_context = work_data->context;
	packet = (struct scm_packet *)&work_data->data;
	packet_len = work_data->packet_len;

	/* Sanity check the length against the packet definition */
	expected_packet_len =
		packet->hdr.payload_len +
		sizeof(struct scm_packet_hdr);
	if (expected_packet_len > packet_len) {
		pr_err("Expected packet size %db, got %db",
			expected_packet_len, packet_len);
		goto exit;
	}

	ack = xaprc00x_proxy_run_host_cmd(packet, proxy_context);

	if (ack) {
		xaprc00x_cmd_out(proxy_context->usb_context, ack,
			sizeof(*ack)+ack->hdr.payload_len);
	}
exit:
	kfree(work);
}

static struct scm_packet *xaprc00x_proxy_run_in_transmit(
	struct scm_packet *packet,
	struct xaprc00x_proxy_context *context)
{
	/**
	 * This is a race condition... Cmd uses the same buffer with no guards.
	 * The solution will be in later revisions when requests are pooled
	 * rather than direct sent.
	 */
	struct scm_packet *ack =
		xaprc00x_get_ack_buf(context->usb_context);

	switch (packet->hdr.opcode) {
	case SCM_OP_TRANSMIT:
		xaprc00x_socket_write(
			packet->hdr.sock_id,
			&packet->scm_payload_none,
			packet->hdr.payload_len,
			context->socket_table);

		xaprc00x_proxy_fill_ack_common(&packet->hdr, ack);
		packet->ack.code = SCM_E_SUCCESS;
		break;
	default:
		ack = NULL;
		break;
	}
	return ack;
}

static void xaprc00x_proxy_process_data(struct work_struct *work)
{
	struct work_data_t *work_data;
	struct xaprc00x_proxy_context *proxy_context;
	struct scm_packet *packet;
	int packet_len;
	struct scm_packet *ack;
	int expected_packet_len;

	work_data = (struct work_data_t *) work;
	proxy_context = work_data->context;
	packet = (struct scm_packet *)&work_data->data;
	packet_len = work_data->packet_len;

	/* Sanity check the length against the packet definition */
	expected_packet_len =
		packet->hdr.payload_len +
		sizeof(struct scm_packet_hdr);
	if (expected_packet_len > packet_len) {
		pr_err("Expected packet size %db, got %db",
			expected_packet_len, packet_len);
		goto exit;
	}

	ack = xaprc00x_proxy_run_in_transmit(packet, proxy_context);

	if (ack) {
		xaprc00x_cmd_out(proxy_context->usb_context, ack,
			sizeof(*ack)+ack->hdr.payload_len);
	}
exit:
	kfree(work);
}
