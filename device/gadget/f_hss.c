// SPDX-License-Identifier: GPL-2.0+
/*
 * f_hss.c -- USB Socket Control Model (HSS) function driver
 *
 * Copyright (C) 2018-2019 Xaptum, Inc.
 */
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

/* NOTE: This file is located in drivers/usb/gadget/ which is part of the include path on kernel builds */
#include <u_f.h>

#include "u_hss.h"


/*
 * The Socket Control Model is protocol for a USB device to manage and use
 * Berkeley/POSIX-style sockets on the host.  It allows the device to
 * communicate with remote servers using the network connection of the host.
 * Currently supported protocols include TCP/IPv4 and TCP/IPv6.
 *
 * The HSS data transfer model uses bulk endpoints (short packet terminated)
 * to send and recieve data from the hosts sockets and interrupt endpoints to
 * communcate socket management data (open, connect, ect).
 */

/*
 * Change to your devices appropiate value and add an entry to the host drivers
 * device table
 */
#define HSS_SUBCLASS 0xab
#define MAX_INT_PACKET_SIZE    64
#define HSS_STATUS_INTERVAL_MS 4 //32
#define HSS_ACK_TIMEOUT 10000

/**
 * Usb function structure definition
 */
struct f_hss {
	struct usb_function function;

	struct usb_ep *bulk_in;
	struct usb_ep *bulk_out;
	struct usb_ep *cmd_out;
	struct usb_ep *cmd_in;
	struct usb_ep *ep0;

	struct usb_request	*req_in;
	struct usb_request	*req_out;
	struct usb_request	*req_bulk_out;

	void *proxy_context;
};

/* Forward declarations */
static void hss_send_int_msg_complete(struct usb_ep *ep, struct usb_request *req);
static int hss_read_out_cmd(struct f_hss *hss_inst);
static int hss_read_out_bulk(struct f_hss *hss_inst);
static void hss_send_int_msg(char *data, size_t len, void *hss_inst);
static void hss_send_bulk_msg(struct hss_packet_hdr *hdr, char *data, size_t len,
	void *hss_inst);


static struct hss_usb_descriptor hss_usb_intf = {
	.hss_cmd=hss_send_int_msg,
	.hss_transfer=hss_send_bulk_msg
};

/*
 * The USB interface descriptor to tell the host
 * how many endpoints are being deviced, ect.
 */
static struct usb_interface_descriptor hss_intf = {
	.bLength            = sizeof(hss_intf),
	.bDescriptorType    = USB_DT_INTERFACE,

	.bNumEndpoints      = 4,
	.bInterfaceClass    = USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass = HSS_SUBCLASS,
	/* .bInterfaceNumber = DYNAMIC */
	/* .iInterface = DYNAMIC */
};

/***************************************************************************
 * USB DESCRIPTOR DEFINITIONS
 * There are 4 descriptors:
 *   Bulk In / Out
 *   Cmd In / Out
 * There are 3 speeds:
 *   Full Speed
 *   High Speed
 *   Super Speed
 * Every combination of the above needs its own descriptor.
 ***************************************************************************/

/**
 * Full speed endpoint descriptors
 */
static struct usb_endpoint_descriptor
fs_hss_cmd_in_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        10,
};

static struct usb_endpoint_descriptor
fs_hss_cmd_out_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        10,
};

static struct usb_endpoint_descriptor fs_hss_in_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes =     USB_ENDPOINT_XFER_BULK,

};

static struct usb_endpoint_descriptor fs_hss_out_desc =  {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes =     USB_ENDPOINT_XFER_BULK,

};

static struct usb_descriptor_header *hss_fs_descs[] = {
	(struct usb_descriptor_header *) &hss_intf,
	(struct usb_descriptor_header *) &fs_hss_in_desc,
	(struct usb_descriptor_header *) &fs_hss_out_desc,
	(struct usb_descriptor_header *) &fs_hss_cmd_in_desc,
	(struct usb_descriptor_header *) &fs_hss_cmd_out_desc,
	NULL,
};

/**
 * High speed descriptors
 */
static struct usb_endpoint_descriptor
hs_hss_cmd_in_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        USB_MS_TO_HS_INTERVAL(HSS_STATUS_INTERVAL_MS),
};

static struct usb_endpoint_descriptor
hs_hss_cmd_out_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        USB_MS_TO_HS_INTERVAL(HSS_STATUS_INTERVAL_MS),
};

static struct usb_endpoint_descriptor hs_hss_in_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =      USB_DT_ENDPOINT,

	.bEndpointAddress =     USB_DIR_IN,
	.bmAttributes =         USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_hss_out_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =      USB_DT_ENDPOINT,

	.bEndpointAddress =     USB_DIR_OUT,
	.bmAttributes =         USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_descriptor_header *hss_hs_descs[] = {
	(struct usb_descriptor_header *) &hss_intf,
	(struct usb_descriptor_header *) &hs_hss_out_desc,
	(struct usb_descriptor_header *) &hs_hss_in_desc,
	(struct usb_descriptor_header *) &hs_hss_cmd_out_desc,
	(struct usb_descriptor_header *) &hs_hss_cmd_in_desc,
	NULL,
};

/**
 * Superspeed descriptors
 */
static struct usb_endpoint_descriptor
ss_hss_cmd_in_desc = {
	.bLength =         USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        USB_MS_TO_HS_INTERVAL(HSS_STATUS_INTERVAL_MS),
};

static struct usb_endpoint_descriptor
ss_hss_cmd_out_desc = {
	.bLength =         USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        USB_MS_TO_HS_INTERVAL(HSS_STATUS_INTERVAL_MS),
};

static struct usb_ss_ep_comp_descriptor ss_hss_cmd_comp_desc = {
	.bLength =		sizeof(ss_hss_cmd_comp_desc),
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.wBytesPerInterval =	cpu_to_le16(MAX_INT_PACKET_SIZE),
};

static struct usb_endpoint_descriptor ss_hss_in_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =      USB_DT_ENDPOINT,

	.bEndpointAddress =     USB_DIR_IN,
	.bmAttributes =         USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_hss_in_comp_desc = {
	.bLength =              USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
	.wBytesPerInterval =    0,
};

static struct usb_endpoint_descriptor ss_hss_out_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =      USB_DT_ENDPOINT,

	.bEndpointAddress =     USB_DIR_OUT,
	.bmAttributes =         USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_hss_out_comp_desc = {
	.bLength =              USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =            0,
	.bmAttributes =         0,
	.wBytesPerInterval =    0,
};

static struct usb_descriptor_header *hss_ss_descs[] = {
	(struct usb_descriptor_header *) &hss_intf,

	(struct usb_descriptor_header *) &ss_hss_out_desc,
	(struct usb_descriptor_header *) &ss_hss_out_comp_desc,

	(struct usb_descriptor_header *) &ss_hss_in_desc,
	(struct usb_descriptor_header *) &ss_hss_in_comp_desc,

	(struct usb_descriptor_header *) &ss_hss_cmd_in_desc,
	(struct usb_descriptor_header *) &ss_hss_cmd_comp_desc,

	(struct usb_descriptor_header *) &ss_hss_cmd_out_desc,
	(struct usb_descriptor_header *) &ss_hss_cmd_comp_desc,
	NULL,
};

/**
 * USB string definitions
 */
static struct usb_string hss_string_defs[] = {
	[0].s = "Socket Control Model (HSS)",
	{  }                    /* end of list */
};

static struct usb_gadget_strings hss_string_table = {
	.language = 0x0409, /* en-us */
	.strings =  hss_string_defs,
};

static struct usb_gadget_strings *hss_strings[] = {
	&hss_string_table,
	NULL,
};

/**
 * usb allocation
 */
static inline struct f_hss *func_to_hss(struct usb_function *f)
{
	return container_of(f, struct f_hss, function);
}

/* Binds this driver to a device */
static int hss_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev;
	struct f_hss *hss;
	int id;
	int ret;

	cdev = c->cdev;
	hss = func_to_hss(f);

	id = usb_interface_id(c, f);
	if (id < 0)
		return -ENODEV;

	hss_intf.bInterfaceNumber = id;

	id = usb_string_id(cdev);
	if (id < 0)
		return -ENODEV;

	hss_string_defs[0].id = id;
	hss_intf.iInterface = id;

	/* Set up the bulk and command endpoints */
	hss->bulk_in = usb_ep_autoconfig(cdev->gadget, &fs_hss_in_desc);
	if (!hss->bulk_in) {
		ERROR(cdev, "%s: can't autoconfigure bulk source on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;

	}

	hss->bulk_out = usb_ep_autoconfig(cdev->gadget, &fs_hss_out_desc);
	if (!hss->bulk_out) {
		ERROR(cdev, "%s: can't autoconfigure bulk sink on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;

	}

	hss->cmd_out = usb_ep_autoconfig(cdev->gadget, &fs_hss_cmd_out_desc);
	if (!hss->cmd_out) {
		ERROR(cdev,
			"%s: can't autoconfigure control source on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;
	}

	hss->cmd_in = usb_ep_autoconfig(cdev->gadget,
		&fs_hss_cmd_in_desc);
	if (!hss->cmd_in) {
		ERROR(cdev, "%s: can't autoconfigure control sink on %s\n",
		f->name, cdev->gadget->name);
		return -ENODEV;
	}


	/* support high speed hardware */
	hs_hss_out_desc.bEndpointAddress =
		fs_hss_out_desc.bEndpointAddress;
	hs_hss_in_desc.bEndpointAddress =
		fs_hss_in_desc.bEndpointAddress;
	hs_hss_cmd_out_desc.bEndpointAddress =
		fs_hss_cmd_out_desc.bEndpointAddress;
	hs_hss_cmd_in_desc.bEndpointAddress =
		fs_hss_cmd_in_desc.bEndpointAddress;

	/* support super speed hardware */
	ss_hss_out_desc.bEndpointAddress =
		fs_hss_out_desc.bEndpointAddress;
	ss_hss_in_desc.bEndpointAddress =
		fs_hss_in_desc.bEndpointAddress;
	ss_hss_cmd_out_desc.bEndpointAddress =
		fs_hss_cmd_out_desc.bEndpointAddress;
	ss_hss_cmd_in_desc.bEndpointAddress =
		fs_hss_cmd_in_desc.bEndpointAddress;

	/* Copy the descriptors to the function */
	ret = usb_assign_descriptors(f, hss_fs_descs, hss_hs_descs,
			hss_ss_descs, NULL);
	if (ret)
		goto fail;

	/* Initialize the proxy and store it's instance for future calls */
	hss->proxy_context = hss_proxy_init(hss, &hss_usb_intf);

	DBG(cdev, "HSS bind complete at %s speed\n",
		gadget_is_superspeed(c->cdev->gadget) ? "super" :
		gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full");
fail:
	return ret;
}

static void hss_free_func(struct usb_function *f)
{
	struct f_hss_opts *opts;

	opts = container_of(f->fi, struct f_hss_opts, func_inst);

	mutex_lock(&opts->lock);
	opts->refcnt--;
	mutex_unlock(&opts->lock);

	usb_free_all_descriptors(f);
	kfree(func_to_hss(f));
}

static int enable_endpoint(struct usb_composite_dev *cdev, struct f_hss *hss,
	struct usb_ep *ep)
{
	int result;

	result = config_ep_by_speed(cdev->gadget, &(hss->function), ep);
	if (result)
		goto out;

	result = usb_ep_enable(ep);
	if (result < 0)
		goto out;
	ep->driver_data = hss;
	result = 0;
out:
	return result;
}

static void disable_ep(struct usb_composite_dev *cdev, struct usb_ep *ep)
{
	int value;

	value = usb_ep_disable(ep);
	if (value < 0)
		DBG(cdev, "disable %s --> %d\n", ep->name, value);
}

static int enable_hss(struct usb_composite_dev *cdev, struct f_hss *hss)
{
	int result = 0;
	// Enable the endpoints
	result = enable_endpoint(cdev, hss, hss->bulk_in);
	if (result) {
		ERROR(cdev, "enable_endpoint for bulk_in failed ret=%d",
			result);
		goto exit;
	}

	result = enable_endpoint(cdev, hss, hss->bulk_out);
	if (result) {
		ERROR(cdev, "enable_endpoint for bulk_out failed ret=%d",
			result);
		goto exit_free_bi;
	}

	result = enable_endpoint(cdev, hss, hss->cmd_in);
	if (result) {
		ERROR(cdev, "enable_endpoint for cmd_in failed ret=%d",
			result);
		goto exit_free_bo;
	}

	result = enable_endpoint(cdev, hss, hss->cmd_out);
	if (result) {
		ERROR(cdev, "enable_endpoint for cmd_out failed ret=%d",
			result);
		goto exit_free_ci;
	}

	hss->req_in = alloc_ep_req(hss->cmd_in, MAX_INT_PACKET_SIZE);
	if (!hss->req_in) {
		ERROR(cdev, "alloc_ep_req for req_in failed");
		result = -ENOMEM;
		goto exit_free_co;
	}
	hss->req_in->context = hss;
	hss->req_in->complete = hss_send_int_msg_complete;

	/* TODO use a better size than +64 */
	hss->req_out = alloc_ep_req(hss->cmd_out, MAX_INT_PACKET_SIZE+64);
	if (!hss->req_out) {
		ERROR(cdev, "alloc_ep_req for req_out failed");
		result = -ENOMEM;
		goto exit_free_ri;
	}

	hss->req_bulk_out = alloc_ep_req(hss->bulk_out, 2048);
	if (!hss->req_bulk_out) {
		ERROR(cdev, "alloc_ep_req for req_bulk_out failed");
		result = -ENOMEM;
		goto exit_free_ri;
	}

	hss_read_out_cmd(hss);
	hss_read_out_bulk(hss);

	goto exit;
exit_free_ri:
	free_ep_req(hss->cmd_in, hss->req_in);
	hss->req_in = NULL;
exit_free_co:
	disable_ep(cdev, hss->cmd_out);
exit_free_ci:
	disable_ep(cdev, hss->cmd_in);
exit_free_bo:
	disable_ep(cdev, hss->bulk_out);
exit_free_bi:
	disable_ep(cdev, hss->bulk_in);
exit:
	return result;
}

static void disable_hss(struct f_hss *hss)
{
	struct usb_composite_dev *cdev;

	if (hss->cmd_in && hss->req_in)
		free_ep_req(hss->cmd_in, hss->req_in);
	hss->req_in = NULL;

	cdev = hss->function.config->cdev;
	disable_ep(cdev, hss->bulk_in);
	disable_ep(cdev, hss->bulk_out);
	disable_ep(cdev, hss->cmd_in);
	disable_ep(cdev, hss->cmd_out);
}

/**
 * Sets the interface alt setting
 * As we have no alt settings yet value will be zero.
 * But interface should be disabled / enabled again
 */
static int hss_set_alt(struct usb_function *f, unsigned int intf,
	unsigned int alt)
{
	int ret;

	struct f_hss *hss = func_to_hss(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	disable_hss(hss);
	ret = enable_hss(cdev, hss);
	if (ret)
		goto exit;

exit:
	return ret;
}

static void hss_disable(struct usb_function *f)
{
	struct f_hss *sock = func_to_hss(f);

	disable_hss(sock);
}

static struct usb_function *hss_alloc(struct usb_function_instance *fi)
{
	struct f_hss_opts *hss_opts;
	struct f_hss *hss;

	hss = kzalloc(sizeof(*hss), GFP_KERNEL);
	if (!hss)
		return ERR_PTR(-ENOMEM);

	hss_opts = container_of(fi, struct f_hss_opts, func_inst);

	mutex_lock(&hss_opts->lock);
	hss_opts->refcnt++;
	mutex_unlock(&hss_opts->lock);

	hss->function.name = "hss";
	hss->function.bind = hss_bind;
	hss->function.set_alt = hss_set_alt;
	hss->function.disable = hss_disable;
	hss->function.strings = hss_strings;

	hss->function.free_func = hss_free_func;

	return &hss->function;
}

/**
 *
 * usb instance allocation handling
 */
static inline struct f_hss_opts *to_f_hss_opts(struct config_item *item)
{
	return container_of(to_config_group(item), struct f_hss_opts,
		func_inst.group);
}

static void hss_attr_release(struct config_item *item)
{
	struct f_hss_opts *hss_opts = to_f_hss_opts(item);

	usb_put_function_instance(&hss_opts->func_inst);
}

static struct configfs_item_operations hss_item_ops = {
	.release                = hss_attr_release,
};

static struct configfs_attribute *hss_attrs[] = {
	NULL,
};

static struct config_item_type hss_func_type = {
		.ct_item_ops    = &hss_item_ops,
		.ct_attrs       = hss_attrs,
		.ct_owner       = THIS_MODULE,
};

static void hss_free_instance(struct usb_function_instance *fi)
{
	struct f_hss_opts *hss_opts;

	hss_opts = container_of(fi, struct f_hss_opts, func_inst);
	kfree(hss_opts);
}

static struct usb_function_instance *hss_alloc_inst(void)
{
	struct f_hss_opts *hss_opts;

	hss_opts = kzalloc(sizeof(*hss_opts), GFP_KERNEL);
	if (!hss_opts)
		return ERR_PTR(-ENOMEM);

	mutex_init(&hss_opts->lock);

	hss_opts->func_inst.free_func_inst = hss_free_instance;

	config_group_init_type_name(&hss_opts->func_inst.group, "",
		&hss_func_type);

	return &hss_opts->func_inst;
}

DECLARE_USB_FUNCTION(hss, hss_alloc_inst, hss_alloc);

static int __init f_hss_init(void)
{
	usb_function_register(&hssusb_func);
	return 0;
}

static void __exit f_hss_exit(void)
{
	usb_function_unregister(&hssusb_func);
}

module_init(f_hss_init);
module_exit(f_hss_exit);

/* Handle USB listening and writing */
static void hss_send_int_msg_complete(struct usb_ep *ep, struct usb_request *req)
{
	kfree(req->buf);
}
static void hss_send_int_msg(char *data, size_t len, void *inst)
{
	struct f_hss *hss_inst = (struct f_hss *)inst;
	struct usb_request *req = hss_inst->req_in;
	int ret;

	if (!req)
		return;

	req->buf = kmalloc(MAX_INT_PACKET_SIZE, GFP_ATOMIC);
	memcpy(req->buf, data, len);
	req->length = len;
	ret = usb_ep_queue(hss_inst->cmd_in, hss_inst->req_in, GFP_ATOMIC);
}

static void hss_send_bulk_msg_complete(struct usb_ep *ep, struct usb_request *req)
{
	kfree(req->buf);
	usb_ep_free_request(ep, req);
}

static void hss_send_bulk_msg(struct hss_packet_hdr *hdr, char *data, size_t len,
	void *inst)
{
	struct f_hss *hss_inst = (struct f_hss*) inst;
	struct usb_request *in_req;
	void *usb_data;
	int total_packet_len = sizeof(*hdr) + len;

	in_req = usb_ep_alloc_request(hss_inst->bulk_in, GFP_KERNEL);
	in_req->length = total_packet_len;
	in_req->complete = hss_send_bulk_msg_complete;

	usb_data = kmalloc(total_packet_len, GFP_KERNEL);
	in_req->buf = usb_data;
	memcpy(in_req->buf, hdr, sizeof(*hdr));
	memcpy(in_req->buf + sizeof(*hdr), data, len);

	usb_ep_queue(hss_inst->bulk_in, in_req, GFP_ATOMIC);
}
static void hss_read_out_cmd_cb(struct usb_ep *ep, struct usb_request *req)
{
	if (req->buf) {
		struct f_hss *ctx = (struct f_hss *)req->context;
		hss_proxy_rcv_cmd(req->buf, req->actual, ctx->proxy_context);
	}
	hss_read_out_cmd(req->context);
}

static void hss_read_out_bulk_cb(struct usb_ep *ep, struct usb_request *req)
{
	if (req->buf) {
		struct f_hss *ctx = (struct f_hss *)req->context;
		hss_proxy_rcv_data(req->buf, req->actual, ctx->proxy_context);
		kfree(req->buf);
	}
	hss_read_out_bulk(req->context);
}

static int hss_read_out_cmd(struct f_hss *hss_inst)
{
	struct usb_request *out_req = hss_inst->req_out;

	out_req->length = sizeof(struct hss_packet) + 64;
	out_req->buf = kmalloc(out_req->length, GFP_ATOMIC);
	out_req->dma = 0;
	out_req->complete = hss_read_out_cmd_cb;
	out_req->context = hss_inst;
	usb_ep_queue(hss_inst->cmd_out, out_req, GFP_ATOMIC);

	return 0;
}

static int hss_read_out_bulk(struct f_hss *hss_inst)
{
	struct usb_request *out_bulk_req = hss_inst->req_bulk_out;

	out_bulk_req->length = 2048;
	out_bulk_req->buf = kmalloc(out_bulk_req->length, GFP_ATOMIC);
	out_bulk_req->dma = 0;
	out_bulk_req->complete = hss_read_out_bulk_cb;
	out_bulk_req->context = hss_inst;
	usb_ep_queue(hss_inst->bulk_out, out_bulk_req, GFP_ATOMIC);
	return 0;
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("HSS Driver");
MODULE_VERSION("0.0.1");
