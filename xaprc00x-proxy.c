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
#include "xaprc00x-packet.h"

struct xaprc00x_proxy_context {
	u16 proxy_id;
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

struct listen_data {
	int sock_id;
	struct xaprc00x_proxy_context *context;
};

/* Forward declarations */
static void xaprc00x_proxy_process_cmd(struct work_struct *work);
static void xaprc00x_proxy_process_data(struct work_struct *work);
int xaprc00x_proxy_listen_socket(void *param);

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
	struct xaprc00x_proxy_context *context = NULL;
	/* Make the name large enough to hold the largest possible value */
	char name[sizeof("scm_data_wq_4294967296")];

	struct workqueue_struct *wq = NULL;
	struct workqueue_struct *data_wq = NULL;
	int dev = xaprc00x_dev_counter++;

	/* Name and allocate the workqueue */
	snprintf(name, sizeof(name), "scm_wq_%d", dev);
	wq = create_workqueue(name);
	if (!wq)
		goto exit;

	snprintf(name, sizeof(name), "scm_data_wq_%d", dev);
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
	xaprc00x_packet_fill_ack_open(packet, ack, ret, payload->handle);
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
	xaprc00x_packet_fill_ack_connect(packet, ack, ret);

	/* Start reading from the socket if we are connected */
	if(!ret) {
		struct task_struct *new_thread;
		/* Spawned thread is expected to free */
		struct listen_data *params = kmalloc(sizeof(struct listen_data),
			GFP_KERNEL);
		params->sock_id = id;
		params->context = context;

		new_thread = kthread_create(
			xaprc00x_proxy_listen_socket,
			params,
			"scm_sk_%d",
			id);
		if(new_thread)
			wake_up_process(new_thread);
	}
}

/* Continually listen to a socket and pass its data over USB */
int xaprc00x_proxy_listen_socket(void *param)
{
	struct listen_data *ld = param;
	int ret = 0;
	int len = 128 + sizeof(struct scm_packet_hdr);
	struct scm_packet *msg = kzalloc(len, GFP_KERNEL);
	struct scm_packet *proxy_cmd_buf;
	char *payload = (void *)msg;
	payload += sizeof(struct scm_packet_hdr);
	int bulk_ret;

	while (1) {
		ret = xaprc00x_socket_read(ld->sock_id, payload, 128, 0,
			ld->context->socket_table);

		if (ret > 0) {
			xaprc00x_packet_fill_transmit(msg, ld->sock_id, NULL, ret);
			bulk_ret = xaprc00x_bulk_out(ld->context->usb_context,
				msg, ret + sizeof(struct scm_packet_hdr));
		} else {
			/* Send a close up to the host */
			xaprc00x_packet_fill_close(msg, ld->sock_id);
			proxy_cmd_buf = xaprc00x_get_ack_buf(ld->context->usb_context);
			memcpy(proxy_cmd_buf, msg, sizeof(*msg));
			xaprc00x_cmd_out(ld->context->usb_context,
				proxy_cmd_buf,sizeof(*msg));
			break;
		}
		/* Zero out the packet (not the payload, though) */
		memset(msg, 0, sizeof(*msg));
	}
	kfree(msg);
	kfree(param);
	return 0;
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

	printk(KERN_INFO "Got CLOSE for socket %d", id);
	xaprc00x_socket_close(id, context->socket_table);

	/* Close ACKs do not contain status data. */
	xaprc00x_packet_fill_ack(hdr, ack);
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

	printk(KERN_INFO "xaprc00x_proxy_rcv_data");

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
	struct scm_packet *ack = kmalloc(sizeof(*ack) + 64, GFP_KERNEL);

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
	struct scm_packet *proxy_cmd_buf;
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
		proxy_cmd_buf = xaprc00x_get_ack_buf(proxy_context->usb_context);
		memcpy(proxy_cmd_buf, ack, sizeof(*ack) + ack->hdr.payload_len);
		xaprc00x_cmd_out(proxy_context->usb_context, proxy_cmd_buf,
			sizeof(*ack)+ack->hdr.payload_len);
		kfree(ack);
	}
exit:
	kfree(work);
}

/**
 * xaprc00x_proxy_run_in_transmit - Handles inbound (from device)
 * TRANSMIT commands
 *
 * @packet The packet to process
 * @context the xaprc00x proxy context
 *
 * Notes: Returns a newly allocated ACK or NULL. Caller must free
 */
static struct scm_packet *xaprc00x_proxy_run_in_transmit(
	struct scm_packet *packet,
	struct xaprc00x_proxy_context *context)
{
	struct scm_packet *ack = kmalloc(sizeof(struct scm_packet), GFP_KERNEL);

	switch (packet->hdr.opcode) {
	case SCM_OP_TRANSMIT:
		xaprc00x_socket_write(packet->hdr.sock_id, &packet->scm_payload_none,
			packet->hdr.payload_len, context->socket_table);

		/* TODO use function to fill positive flow code when implemented */
		xaprc00x_packet_fill_ack(&packet->hdr, ack);
		packet->ack.code = SCM_E_SUCCESS;
		break;
	default:
		ack = NULL;
		kfree(ack);
		break;
	}
	return ack;
}

/**
 * xaprc00x_proxy_process_data - Handles inbound (from device)
 * data type packets
 *
 * @work The work struct, expected type `struct xaprc00x_proxy_context`
 */
static void xaprc00x_proxy_process_data(struct work_struct *work)
{
	struct work_data_t *work_data;
	struct xaprc00x_proxy_context *proxy_context;
	struct scm_packet *packet;
	int packet_len;
	struct scm_packet *ack = NULL;
	struct scm_packet *proxy_cmd_buf;
	int expected_packet_len;

	printk(KERN_INFO "xaprc00x_proxy_process_data");

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
		proxy_cmd_buf = xaprc00x_get_ack_buf(proxy_context->usb_context);
		memcpy(proxy_cmd_buf, ack, sizeof(*ack));
		xaprc00x_cmd_out(proxy_context->usb_context, ack,
			sizeof(*ack)+ack->hdr.payload_len);
	}
exit:
	kfree(work);
	kfree(ack);
}
