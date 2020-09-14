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

/**
 * hss_proxy_assign_ip4 - Assign an IPv4 address to an HSS packet
 *
 * @packet The packet being written to
 * @addr The socket address
 *
 * Fills the packets connect member to the information given in the
 * addr parameter.
 *
 */
static void hss_proxy_assign_ip4(struct hss_packet *packet,
	struct sockaddr *addr)
{
	struct sockaddr_in *ip4_addr = (struct sockaddr_in *) addr;

	packet->connect.addr.ip4.ip_addr = ip4_addr->sin_addr.s_addr;
	packet->connect.port = ip4_addr->sin_port;
	packet->connect.family = HSS_FAM_IP;

	packet->hdr.payload_len = sizeof(struct hss_payload_connect_ip) -
		sizeof(union hss_payload_connect_ip_addr) +
		sizeof(struct hss_payload_connect_ip4);
}

/**
 * hss_proxy_assign_ip6 - Assign an IPv6 address to an HSS packet
 *
 * @packet The packet being written to
 * @addr The socket address
 *
 * Fills the packets connect member to the information given in the
 * addr parameter.
 *
 */
static void hss_proxy_assign_ip6(struct hss_packet *packet,
	struct sockaddr *addr)
{
	struct sockaddr_in6 *ip6_addr = (struct sockaddr_in6 *) addr;

	memcpy(packet->connect.addr.ip6.ip_addr,
		&ip6_addr->sin6_addr, sizeof(struct in6_addr));
	packet->connect.port = ip6_addr->sin6_port;
	packet->connect.addr.ip6.scope_id = ip6_addr->sin6_scope_id;
	packet->connect.addr.ip6.flow_info = ip6_addr->sin6_flowinfo;
	packet->connect.family = HSS_FAM_IP6;

	packet->hdr.payload_len = sizeof(struct hss_payload_connect_ip) -
		sizeof(union hss_payload_connect_ip_addr) +
		sizeof(struct hss_payload_connect_ip6);
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
 */
 void hss_proxy_recv_ack(struct hss_packet *packet, void *inst)
{
	struct hss_proxy_work *new_work;
	struct hss_proxy_inst *proxy_inst;

	/* The work item will be cleared at thend of the job */
	new_work = kmalloc(sizeof(*new_work), GFP_ATOMIC);
	if (!new_work)
		return;
	new_work->proxy_context = inst;

	/**
	 * This packet will be freed when the socket no longer needs it
	 * which may be after the workqueue is done
	 */
	new_work->packet = kmalloc(sizeof(*packet), GFP_ATOMIC);
	if (!new_work->packet) {
		kfree(new_work);
		return;
	}
	memcpy(new_work->packet, packet, sizeof(*packet));

	proxy_inst = inst;

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
		kfree(new_work->packet);
		kfree(new_work);
		break;
	}
}

void hss_proxy_recv_transmit(struct hss_packet *packet, void *inst)
{
	struct hss_proxy_work *new_work;
	struct hss_proxy_inst *proxy_inst;
	int data_packet_len;
	/* The work item will be cleared at thend of the job */

	new_work = kmalloc(sizeof(*new_work), GFP_ATOMIC);

	if (!new_work)
		return;

	new_work->proxy_context = inst;

	/**
	 * This packet will be freed when the socket no longer needs it
	 * which may be after the workqueue is done
	 */
	data_packet_len = sizeof(struct hss_packet_hdr) +
		packet->hdr.payload_len;
	new_work->packet = kmalloc(
		data_packet_len,
		GFP_ATOMIC);
	if (!new_work->packet) {
		kfree(new_work);
		return;
	}
	memcpy(new_work->packet, packet, data_packet_len);

	proxy_inst = inst;

	INIT_WORK(&new_work->work, hss_proxy_process_transmit);
	queue_work(proxy_inst->data_wq, &new_work->work);
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
void hss_proxy_recv_close(struct hss_packet *packet, void *inst)
{
	struct hss_proxy_work *new_work;
	struct hss_proxy_inst *proxy_inst;

	/* The work item will be cleared at thend of the job */
	new_work = kmalloc(sizeof(*new_work), GFP_ATOMIC);
	if (!new_work)
		return;
	new_work->proxy_context = inst;

	/* CLOSE does not have any fields */
	new_work->packet = kmalloc(sizeof(*packet), GFP_ATOMIC);
	if (!new_work->packet) {
		kfree(new_work);
		return;
	}
	memcpy(new_work->packet, packet, sizeof(*packet));

	proxy_inst = inst;

	/* Queue a work item to handle the incoming packet */
	INIT_WORK(&new_work->work, hss_proxy_process_close);
	queue_work(proxy_inst->ack_wq, &new_work->work);
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
	struct hss_packet *packet = kzalloc(sizeof(struct hss_packet),
		GFP_KERNEL);
	int ret;
	struct hss_payload_ack ack;
	struct hss_proxy_inst *proxy_inst;

	proxy_inst = context;

	packet->hdr.opcode = HSS_OP_CONNECT;
	packet->hdr.msg_id = hss_proxy_get_msg_id(context);
	packet->hdr.sock_id = local_id;

	if (addr->sa_family == AF_INET)
		hss_proxy_assign_ip4(packet, addr);
	else if (addr->sa_family == AF_INET6)
		hss_proxy_assign_ip6(packet, addr);

	proxy_inst->usb_intf->hss_cmd((char*)packet,
		sizeof(struct hss_packet_hdr) + packet->hdr.payload_len,
		proxy_inst->usb_context);

	kfree(packet);

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
	struct hss_packet *packet = kzalloc(sizeof(struct hss_packet),
		GFP_ATOMIC);
	int ret;
	struct hss_payload_ack ack;
	struct hss_proxy_inst *proxy_inst;

	proxy_inst = context;

	packet->hdr.opcode = HSS_OP_OPEN;
	packet->hdr.msg_id = hss_proxy_get_msg_id(proxy_inst);
	packet->hdr.payload_len = sizeof(struct hss_payload_open);
	packet->open.addr_family = HSS_FAM_IP;
	packet->open.protocol = HSS_PROTO_TCP;
	packet->open.type = HSS_TYPE_STREAM;
	packet->open.handle = local_id;

	proxy_inst->usb_intf->hss_cmd((char*)packet, sizeof(struct hss_packet),
		proxy_inst->usb_context);

	return 0;
}


/**
 * hss_proxy_close_socket - Close a HSS socket on the host
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
	struct hss_packet *packet = kzalloc(sizeof(struct hss_packet),
		GFP_KERNEL);
	struct hss_proxy_inst *proxy_inst;

	proxy_inst = context;

	packet->hdr.opcode = HSS_OP_CLOSE;
	packet->hdr.msg_id = hss_proxy_get_msg_id(context);
	packet->hdr.sock_id = local_id;
	packet->hdr.payload_len = 0;

	proxy_inst->usb_intf->hss_cmd((char*)packet, sizeof(struct hss_packet_hdr),
		proxy_inst->usb_context);

	kfree(packet);
}

int hss_proxy_write_socket(int sock_id, void *msg, int len, void *context)
{
	struct hss_proxy_inst *proxy_inst;
	struct hss_packet_hdr packet;

	proxy_inst = context;

	packet.opcode = HSS_OP_TRANSMIT;
	packet.msg_id = hss_proxy_get_msg_id(context);
	packet.sock_id = sock_id;
	packet.payload_len = len;

	proxy_inst->usb_intf->hss_transfer(&packet, (char*)msg, len,
		proxy_inst->usb_context);
	return len;
}



/*
 * Reads HSS command from the host
 * Note: Called in an atomic context
 */
void hss_proxy_rcv_cmd(struct hss_packet *packet, size_t len,
	void *proxy_context)
{
	/**
	 *Make sure the packet is big enough for the packet and payload
	 * (checked in order to avoid reading bad memory)
	 */
	if (!packet || len < sizeof(*packet) ||
		len > (sizeof(*packet)+packet->hdr.payload_len))
		return;

	/* Incoming command is either a close notificaiton or ACK */
	switch (packet->hdr.opcode) {
	case HSS_OP_ACK:
		hss_proxy_recv_ack(packet, proxy_context);
		break;
	case HSS_OP_CLOSE:
		hss_proxy_recv_close(packet, proxy_context);
		break;
	default:
		pr_err("%s got unexpected packet %d",
			__func__, packet->hdr.opcode);
		break;
	}
}
EXPORT_SYMBOL_GPL(hss_proxy_rcv_cmd);

void hss_proxy_rcv_data(struct hss_packet *packet, size_t len,
	void *proxy_context)
{
	/**
	 *Make sure the packet is big enough for the packet and payload
	 * (checked in order to avoid reading bad memory)
	 */
	if (!packet || len < sizeof(struct hss_packet_hdr) ||
		len > (sizeof(struct hss_packet_hdr)+packet->hdr.payload_len)) {
		return;
	}

	/* Incoming command is either a close notificaiton or ACK */
	switch (packet->hdr.opcode) {
	case HSS_OP_TRANSMIT:
		hss_proxy_recv_transmit(packet, proxy_context);
		break;
	default:
		pr_err("%s got opcode %d", __func__, packet->hdr.opcode);
		break;
	}
}
EXPORT_SYMBOL_GPL(hss_proxy_rcv_data);
