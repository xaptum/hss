#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/usb/composite.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/hss.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/hss.h>

/* HSS Proxy internal functions */
struct hss_proxy_inst {
	void *usb_context;
	struct hss_usb_descriptor *usb_intf;
	atomic_t hss_msg_id;
	spinlock_t ack_list_lock;
	struct workqueue_struct *ack_wq;
	struct workqueue_struct *data_wq;
	struct list_head ack_list;
	char *carry_pkt; /* A persistent holder for a single HSS packet that has been split into multiple USB transfers */
	int carry_pkt_len;
};

struct hss_proxy_work {
	struct work_struct work;
	void *proxy_context;
	struct hss_packet *packet;
};

/* For naming the ACK workqueue */
static atomic_t g_proxy_counter;

/**
 * hss_proxy_get_msg_id - Gets a unique message ID for outgoing messages
 *
 * @proxy_context The HSS proxy context
 *
 * Returns: Unique message ID
 *
 */
static int hss_proxy_get_msg_id(struct hss_proxy_inst *proxy_context)
{
	__u16 id;
	/*
	 * Note: This operation is defined in the Kernel as 2s compliment
	 * overflow (INT_MAX+1==INT_MIN) becuase the kernel uses
	 * -fno-strict-overflow
	 */
	id = atomic_inc_return(&proxy_context->hss_msg_id);
	return id;
}

static void hss_proxy_process_open_ack(struct work_struct *work)
{
	struct hss_proxy_work *work_data;

	work_data = (struct hss_proxy_work *)work;
	hss_sock_open_ack(work_data->packet->hdr.sock_id,
		work_data->packet);
	kfree(work);
}

static void hss_proxy_process_connect_ack(struct work_struct *work)
{
	struct hss_proxy_work *work_data;

	work_data = (struct hss_proxy_work *)work;
	hss_sock_connect_ack(work_data->packet->hdr.sock_id,
		work_data->packet);
	kfree(work);
}

/**
 * An incoming CLOSE packet means that the server has stopped talking to us so
 * we run a shutdown on our end.
 */
static void hss_proxy_process_close(struct work_struct *work)
{
	struct hss_proxy_work *work_data;

	work_data = (struct hss_proxy_work *) work;
	hss_sock_handle_host_side_shutdown(
		work_data->packet->hdr.sock_id, 2);

	/* Freed here becuase the handler has no use for the packet */
	kfree(work_data->packet);
	kfree(work_data);
}

static void hss_proxy_process_transmit(struct work_struct *work)
{
	struct hss_proxy_work *work_data;

	work_data = (struct hss_proxy_work *)work;
	hss_sock_transmit(work_data->packet->hdr.sock_id,
		&work_data->packet->hss_payload_none,
		work_data->packet->hdr.payload_len);
}

/**
 * hss_proxy_recv_ack - Recieves an ACK message
 *
 * @packet The packet to process
 * @context The HSS proxy context
 *
 * Processes an HSS ACK packet. The `packet` parameter may be modified or
 * free'd after this functions returns.
 *
 * Returns: 0 on success, 1 on failure (indicating it will not free packet)
 *
 */
 int hss_proxy_recv_ack(struct hss_packet *packet, void *inst)
{
	struct hss_proxy_work *new_work;
	struct hss_proxy_inst *proxy_inst;
	int ret = 0;

	proxy_inst = inst;

	/* The work item will be cleared at the end of the job */
	new_work = kmalloc(sizeof(*new_work), GFP_ATOMIC);
	if (!new_work) {
		ret = 1;
		goto out;
	}
	new_work->proxy_context = proxy_inst;
	new_work->packet = packet;

	/* Queue a work item to handle the incoming packet */
	switch (packet->ack.orig_opcode) {
	case HSS_OP_OPEN:
		INIT_WORK(&new_work->work, hss_proxy_process_open_ack);
		queue_work(proxy_inst->ack_wq, &new_work->work);
		break;
	case HSS_OP_CONNECT:
		INIT_WORK(&new_work->work, hss_proxy_process_connect_ack);
		queue_work(proxy_inst->ack_wq, &new_work->work);
		break;
	case HSS_OP_CLOSE: /* Device does not care if the host ACKs */
	default:
		kfree(new_work);
		ret = 1;
		break;
	}

out:
	return ret;
}


/**
 * hss_proxy_recv_transmit - Recieves an TRANSMIT message
 *
 * @packet The packet to process
 * @context The HSS proxy context
 *
 * Processes an HSS TRANSMIT packet.
 *
 */
int hss_proxy_recv_transmit(struct hss_packet *packet, void *inst)
{
	struct hss_proxy_work *new_work;
	struct hss_proxy_inst *proxy_inst;
	int data_packet_len;
	int ret = 0;

	proxy_inst = inst;

	/* The work item will be cleared at thend of the job */
	new_work = kmalloc(sizeof(*new_work), GFP_ATOMIC);

	if (!new_work) {
		ret = 1;
		goto out;
	}

	new_work->proxy_context = proxy_inst;
	new_work->packet = packet;

	INIT_WORK(&new_work->work, hss_proxy_process_transmit);
	queue_work(proxy_inst->data_wq, &new_work->work);

out:
	return ret;
}

/**
 * hss_proxy_recv_close - Recieves an CLOSE message
 *
 * @packet The packet to process
 * @context The HSS proxy context
 *
 * Processes an HSS CLOSE packet. The `packet` parameter may be modified or
 * free'd after this functions returns.
 *
 */
int hss_proxy_recv_close(struct hss_packet *packet, void *inst)
{
	struct hss_proxy_work *new_work;
	struct hss_proxy_inst *proxy_inst;
	int ret = 0;

	proxy_inst = inst;

	/* The work item will be cleared at the end of the job */
	new_work = kmalloc(sizeof(*new_work), GFP_ATOMIC);
	if (!new_work) {
		ret = 1;
		goto out;
	}
	new_work->proxy_context = proxy_inst;
	new_work->packet = packet;

	/* Queue a work item to handle the incoming packet */
	INIT_WORK(&new_work->work, hss_proxy_process_close);
	queue_work(proxy_inst->ack_wq, &new_work->work);

out:
	return ret;
}

/**
 * hss_proxy_init - Initializes an instance of the HSS proxy
 *
 * @usb_context The USB context to link with this proxy instance
 *
 * Initializes an instance of the HSS proxy to allow the HSS USB driver to talk
 * to the HSS network driver. The pointer returned by this function must be
 * passed to all other exported proxy functions as the "proxy context" to allow
 * the proxy to know which instance the operation is being performed on.
 *
 * Returns: A pointer to the instance for this proxy.
 *
 */
void *hss_proxy_init(void *usb_context, struct hss_usb_descriptor *intf)
{
	struct hss_proxy_inst *proxy_inst;

	/* Create a name that can contain the counter */
	char hss_wq_name[sizeof("hss_wq_4294967296")];
	char hss_data_wq_name[sizeof("hss_data_wq_4294967296")];

	proxy_inst = kzalloc(sizeof(struct hss_proxy_inst), GFP_KERNEL);
	if (!proxy_inst)
		return NULL;
	proxy_inst->usb_context = usb_context;

	snprintf(hss_wq_name, sizeof(hss_wq_name), "hss_wq_%d",
		atomic_inc_return(&g_proxy_counter));
	snprintf(hss_wq_name, sizeof(hss_wq_name), "hss_data_wq_%d",
		atomic_inc_return(&g_proxy_counter));

	proxy_inst->ack_wq = create_workqueue(hss_wq_name);
	proxy_inst->data_wq = create_workqueue(hss_data_wq_name);

	spin_lock_init(&proxy_inst->ack_list_lock);
	INIT_LIST_HEAD(&proxy_inst->ack_list);

	proxy_inst->usb_intf = intf;

	/* Start up the Xaptum HSS socket module */
	hss_register(proxy_inst);

	return proxy_inst;
}
EXPORT_SYMBOL_GPL(hss_proxy_init);

/**
 * hss_proxy_connect_socket - Connect an HSS socket
 *
 * @local_id The ID of the socket to close
 * @addr The socket address
 * @alen Address length in bytes
 * @context The HSS proxy context
 *
 * Sends a command to the device to connect an HSS socket to a given address.
 *
 * Returns: 0 on success or returned HSS error code.
 *
 */
int hss_proxy_connect_socket(int local_id, struct sockaddr *addr, int alen,
	void *context)
{
	struct hss_packet packet;
	struct hss_proxy_inst *proxy_inst;
	char hss_out[HSS_FIXED_LEN_CONN_IP6];

	proxy_inst = context;

	hss_packet_fill_connect(&packet, hss_proxy_get_msg_id(context), local_id,
		addr);
	hss_packet_to_buf(&packet, hss_out, HSS_COPY_FIELDS);

	proxy_inst->usb_intf->hss_cmd(hss_out,
		HSS_HDR_LEN + packet.hdr.payload_len,
		proxy_inst->usb_context);

	return 0;
}

/**
 * hss_proxy_open_socket - Open an HSS socket
 *
 * @local_id The ID of the new socket
 * @context The HSS proxy context
 *
 * Sends a command to the device to open an HSS socket.
 *
 * Returns: 0 on success or returned HSS error code. Writes the new sockets
 * local ID to *local_id
 *
 */
int hss_proxy_open_socket(int local_id, void *context)
{
	struct hss_packet packet;
	int ret;
	struct hss_proxy_inst *proxy_inst;
	char hss_send[HSS_FIXED_LEN_OPEN];

	proxy_inst = context;

	hss_packet_fill_open(&packet, HSS_FAM_IP, HSS_PROTO_TCP, HSS_TYPE_STREAM,
		local_id, hss_proxy_get_msg_id(proxy_inst));
	hss_packet_to_buf(&packet, hss_send, HSS_COPY_FIELDS);

	proxy_inst->usb_intf->hss_cmd(hss_send, HSS_FIXED_LEN_OPEN,
		proxy_inst->usb_context);

	return 0;
}


/**
 * hss_proxy_close_socket - Close a HSS socket on the host
 * on behalf of the device side socket
 *
 * @local_id The ID of the socket to close
 * @context The HSS proxy context
 *
 * Sends a command to the device to close a HSS socket.
 *
 */
void hss_proxy_close_socket(int local_id, void *context)
{
	struct hss_packet *ack;
	struct hss_packet packet;
	struct hss_proxy_inst *proxy_inst;
	char hss_out[HSS_FIXED_LEN_CLOSE];

	proxy_inst = context;

	hss_packet_fill_close(&packet, local_id, hss_proxy_get_msg_id(context));
	hss_packet_to_buf(&packet, hss_out, HSS_COPY_FIELDS);

	proxy_inst->usb_intf->hss_cmd(hss_out, HSS_FIXED_LEN_CLOSE,
		proxy_inst->usb_context);
}

int hss_proxy_write_socket(int sock_id, void *msg, int len, void *context)
{
	struct hss_proxy_inst *proxy_inst;
	struct hss_packet packet;
	char hss_out[HSS_FIXED_LEN_TRANSMIT];

	proxy_inst = context;

	hss_packet_fill_transmit(&packet, sock_id, NULL, len,
		hss_proxy_get_msg_id(context));
	hss_packet_to_buf(&packet, hss_out, HSS_COPY_FIELDS);

	proxy_inst->usb_intf->hss_transfer(hss_out, HSS_FIXED_LEN_TRANSMIT,
		(char*)msg, len, proxy_inst->usb_context);
	return len;
}



/*
 * Reads HSS command from the host
 * Note: Called in an atomic context
 */
void hss_proxy_rcv_cmd(char *buf, size_t len,
	void *proxy_context)
{
	struct hss_packet *packet;

	/* Make sure at least a header came in */
	if (!buf || len < HSS_HDR_LEN)
		return;

	packet = kmalloc(HSS_HDR_LEN, GFP_ATOMIC);
	hss_packet_from_buf(packet, buf, HSS_COPY_HDR);

	/* Make sure the entire packet came in */
	if(len != HSS_HDR_LEN + packet->hdr.payload_len)
		goto out_free;

	if (len > HSS_HDR_LEN) {
		packet = krealloc(packet, HSS_HDR_LEN + packet->hdr.payload_len,
			GFP_ATOMIC);
		hss_packet_from_buf(packet, buf, HSS_COPY_FIELDS);

		/* ACK is the only command op that can have an arbitrary payload */
		if (packet->hdr.opcode == HSS_OP_ACK)
			memcpy(packet->ack.empty, buf + HSS_FIXED_LEN_ACK,
				packet->hdr.payload_len - HSS_FIXED_LEN_ACK + HSS_HDR_LEN);
	}

	/* Incoming command is either a close notificaiton or ACK */
	switch (packet->hdr.opcode) {
	case HSS_OP_ACK:
		if (hss_proxy_recv_ack(packet, proxy_context) == 1)
			goto out_free;
		break;
	case HSS_OP_CLOSE:
		if (hss_proxy_recv_close(packet, proxy_context) == 1)
			goto out_free;
		break;
	default:
		pr_err("%s got unexpected packet %d",
			__func__, packet->hdr.opcode);
		goto out_free;
		break;
	}
	goto out;

out_free:
	kfree(packet);
out:
	return;
}
EXPORT_SYMBOL_GPL(hss_proxy_rcv_cmd);

static void hss_proxy_carry(struct hss_proxy_inst *proxy_inst, char *buf, int len)
{
	proxy_inst->carry_pkt = krealloc(
			proxy_inst->carry_pkt,
			proxy_inst->carry_pkt_len + len,
			GFP_KERNEL);
	memcpy(proxy_inst->carry_pkt + proxy_inst->carry_pkt_len, buf, len);
	proxy_inst->carry_pkt_len += len;
}

static void hss_proxy_end_carry(struct hss_proxy_inst *proxy_inst)
{
	kfree(proxy_inst->carry_pkt);
	proxy_inst->carry_pkt = NULL;
	proxy_inst->carry_pkt_len = 0;
}

void hss_proxy_rcv_data(char *buf, size_t len,
	void *proxy_context)
{
	struct hss_packet *packet;
	struct hss_proxy_inst *proxy_inst;

	if (!buf)
		return;

	proxy_inst = proxy_context;

	/* If in a carryover situation, copy the incoming data and replace `buf` with the persistent buffer */
	if (proxy_inst->carry_pkt) {
		printk("%s in carryover, stored=%d, incoming=%d", __func__, proxy_inst->carry_pkt_len, len);
		hss_proxy_carry(proxy_inst, buf, len);

		/* Replace the incoming buffer with the persistent values and continue as normal */
		buf = proxy_inst->carry_pkt;
		len  = proxy_inst->carry_pkt_len;
	}

	/* Make sure at least a header has come in before continuing */
	if(len < HSS_HDR_LEN) {
		/* Start a carryover if not already in one */
		if (!proxy_inst->carry_pkt) {
			printk("%s starting partial hdr carryover, len=%d", __func__, len);
			hss_proxy_carry(proxy_inst, buf, len);
		}
		goto out;
	}

	packet = kmalloc(sizeof(struct hss_packet), GFP_ATOMIC);
	hss_packet_from_buf(packet, buf, HSS_COPY_HDR);

	/* Make sure the entire packet has come through */
	if(len < HSS_HDR_LEN + packet->hdr.payload_len) {
		printk("%s incomplete packet\n", __func__);
		/* Start a carryover if not already in one */
		if (!proxy_inst->carry_pkt) {
			printk("%s starting partial packet carryover, len=%d", __func__, len);
			hss_proxy_carry(proxy_inst, buf, len);
		}
		goto out_free;
	}

	switch (packet->hdr.opcode) {
	case HSS_OP_TRANSMIT:
		/* Reallocate the header to a buffer with enough space to copy the payload */
		packet = krealloc(packet,
			HSS_HDR_LEN + packet->hdr.payload_len, GFP_ATOMIC);
		memcpy(packet->hss_payload_none, buf + HSS_HDR_LEN, packet->hdr.payload_len);

		/* Shedule handling of this operation */
		if (hss_proxy_recv_transmit(packet, proxy_context) == 1)
			goto out_free;
		break;
	default:
		pr_err("%s got opcode %d", __func__, packet->hdr.opcode);
		goto out_free;
		break;
	}
	/* Clear the carry packet conditions */
	hss_proxy_end_carry(proxy_inst);

	goto out;
out_free:
	kfree(packet);
out:
	return;
}
EXPORT_SYMBOL_GPL(hss_proxy_rcv_data);
