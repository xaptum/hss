// SPDX-License-Identifier: GPL-2.0+
/**
 * @file hss_usb.c
 * @brief Implementation of the usb driver part for the xaptum tcp proxy
 *        Based of the usb-skeleton code
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/usb/cdc.h>
#include <linux/workqueue.h>

#include "hss-usb.h"
#include "hss-backports.h"
#include "hss-proxy.h"
#include "hss.h"

/* Match on vendor ID, interface class and interface subclass only. */
static const struct usb_device_id hss_device_table[] = {
	{ USB_VENDOR_AND_INTERFACE_INFO(
			USB_VENDOR_ID_XAPTUM,
			USB_CLASS_VENDOR_SPEC,
			USB_SUBCLASS_HSS_XAPTUM,
			USB_CDC_PROTO_NONE)
	}, { }
};
MODULE_DEVICE_TABLE(usb, hss_device_table);

/* Structure to hold all of our device specific stuff */
struct usb_hss {
	struct usb_device	*udev;
	struct usb_interface	*interface;
	struct semaphore	int_out_sem;
	struct semaphore	bulk_out_sem;
	__u8			bulk_in_endpointAddr;
	__u8			bulk_out_endpointAddr;
	__u8			cmd_in_endpointAddr;
	__u8			cmd_out_endpointAddr;
	int			cmd_interval;
	struct kref		kref;
	char			*cmd_in_buffer;
	void			*cmd_out_buffer;
	char			*bulk_in_buffer;
	void			*bulk_out_buffer;
	struct urb		*cmd_in_urb;
	struct urb		*cmd_out_urb;
	struct urb		*bulk_in_urb;
	struct urb		*bulk_out_urb;
	void			*proxy_context;
};

#define to_hss_dev(d) container_of(d, struct usb_hss, kref)

/* Forward declarations */
static int hss_read_cmd(struct usb_hss *dev);

/********************************************************************
 * USB Driver Operations
 ********************************************************************/

static void hss_driver_delete(struct kref *kref)
{
	struct usb_hss *dev = to_hss_dev(kref);

	usb_put_dev(dev->udev);
	kfree(dev);
}

/**
 * hss_assign_endpoints - Find common bulk and int endpoints
 *
 * @dev The device to search
 *
 * Finds the first available in and out endpoints for both bulk and interrupt.
 *
 * Returns: 0 if all endpoints were matched, -ENXIO otherwise
 *
 */
static int hss_assign_endpoints(struct usb_hss *dev)
{
	struct usb_endpoint_descriptor *ep_cmd_in, *ep_cmd_out;
	struct usb_endpoint_descriptor *ep_bulk_in, *ep_bulk_out;
	int error;

	error = usb_find_common_endpoints(dev->interface->cur_altsetting,
			&ep_bulk_in, &ep_bulk_out, &ep_cmd_in, &ep_cmd_out);

	if (!error) {
		/* Store the endpoint addresses */
		dev->cmd_in_endpointAddr = ep_cmd_in->bEndpointAddress;
		dev->cmd_out_endpointAddr = ep_cmd_out->bEndpointAddress;
		dev->bulk_in_endpointAddr = ep_bulk_in->bEndpointAddress;
		dev->bulk_out_endpointAddr = ep_bulk_out->bEndpointAddress;
		dev->cmd_interval = ep_cmd_in->bInterval;
	} else {
		dev_err(&dev->interface->dev,
			"Could not find all endpoints cmd_in=%s cmd_out=%s bulk_in=%s bulk_out=%s\n",
			(ep_cmd_in ? "found" : "(null)"),
			(ep_cmd_out ? "found" : "(null)"),
			(ep_bulk_in ? "found" : "(null)"),
			(ep_bulk_out ? "found" : "(null)"));
	}

	return error;
}

/**
 * Probe function called when device with correct vendor / productid is found
 */
static int hss_driver_probe(struct usb_interface *interface,
			const struct usb_device_id *id)
{
	struct usb_hss *dev;
	int retval = 0;

	/* Allocate and initialize the device */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	kref_init(&dev->kref);

	dev->udev = usb_get_dev(interface_to_usbdev(interface));
	dev->interface = interface;

	/* Set up the bulk and interrupt endpoints */
	retval = hss_assign_endpoints(dev);
	if (retval)
		goto error;

	dev->cmd_in_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!dev->cmd_in_urb) {
		retval = -ENOMEM;
		dev_err(&dev->interface->dev, "Error for cmd_in_urb");
		goto error;
	}

	dev->cmd_out_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!dev->cmd_out_urb) {
		retval = -ENOMEM;
		dev_err(&dev->interface->dev, "Error for cmd_out_urb");
		goto error_free_in_urb;
	}

	dev->bulk_in_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!dev->bulk_in_urb) {
		retval = -ENOMEM;
		dev_err(&dev->interface->dev, "Error for bulk_in_urb");
		goto error;
	}

	dev->bulk_out_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!dev->bulk_out_urb) {
		retval = -ENOMEM;
		dev_err(&dev->interface->dev, "Error for bulk_out_urb");
		goto error_free_in_urb;
	}

	dev->cmd_in_buffer = usb_alloc_coherent(dev->udev,
		sizeof(struct hss_packet), GFP_KERNEL,
		&dev->cmd_in_urb->transfer_dma);
	if (!dev->cmd_in_buffer) {
		retval = -ENOMEM;
		goto error_free_out_urb;
	}

	dev->cmd_out_buffer = usb_alloc_coherent(dev->udev,
		sizeof(struct hss_packet), GFP_KERNEL,
		&dev->cmd_out_urb->transfer_dma);
	if (!dev->cmd_out_buffer) {
		retval = -ENOMEM;
		goto error_free_in_buf;
	}

	dev->bulk_in_buffer = usb_alloc_coherent(dev->udev,
		XAPRC00X_BULK_IN_BUF_SIZE,
		GFP_KERNEL, &dev->bulk_in_urb->transfer_dma);
	if (!dev->bulk_in_buffer) {
		retval = -ENOMEM;
		goto error_free_in_buf;
	}

	dev->bulk_out_buffer = usb_alloc_coherent(dev->udev,
		XAPRC00X_BULK_OUT_BUF_SIZE,
		GFP_KERNEL, &dev->bulk_out_urb->transfer_dma);
	if (!dev->bulk_out_buffer) {
		retval = -ENOMEM;
		goto error_free_in_buf;
	}

	/* Zero fill the out buffer */
	memset(dev->cmd_out_buffer, 0, sizeof(struct hss_packet) + 64);

	/* Tell the USB interface where our device data is located */
	usb_set_intfdata(interface, dev);

	/* let the user know what node this device is now attached to */
	dev_info(&interface->dev, "HSS Driver now attached.");

	/* Initialize the host proxy and hold on to its instance */
	dev->proxy_context = hss_proxy_init(dev);
	if (!dev->proxy_context) {
		retval = -ENODEV;
		goto error_free_out_buf;
	}

	sema_init(&dev->int_out_sem, 1);
	sema_init(&dev->bulk_out_sem, 1);

	/* Start listening for commands */
	hss_read_cmd(dev);

	return 0;

error_free_out_buf:
	usb_free_coherent(dev->udev, sizeof(struct hss_packet),
		dev->cmd_out_buffer, dev->cmd_out_urb->transfer_dma);
error_free_in_buf:
	usb_free_coherent(dev->udev, sizeof(struct hss_packet),
		dev->cmd_in_buffer, dev->cmd_in_urb->transfer_dma);
error_free_out_urb:
	usb_free_urb(dev->cmd_out_urb);
error_free_in_urb:
	usb_free_urb(dev->cmd_in_urb);
error:
	kref_put(&dev->kref, hss_driver_delete);

	return retval;
}

static void hss_read_cmd_callback(struct urb *urb)
{
	struct usb_hss *dev = urb->context;

	if (urb->status == 0) {
		hss_proxy_rcv_cmd((char *)dev->cmd_in_buffer,
			urb->actual_length, dev->proxy_context);
		usb_submit_urb(urb, GFP_KERNEL);
	}
}

static void hss_read_bulk_callback(struct urb *urb)
{
	struct usb_hss *dev = urb->context;

	switch (urb->status) {
	/* Success */
	case 0:
		hss_proxy_rcv_data((char *)dev->bulk_in_buffer,
			urb->actual_length, dev->proxy_context);
		usb_submit_urb(urb, GFP_KERNEL);
		break;
	/* Unrecoverable errors */
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		dev_err(&dev->interface->dev,
			"Bulk listen CB urb terminated, status: %d\n",
			urb->status);
		break;
	/* Recoverable errors */
	default:
		dev_info(&dev->interface->dev,
			"Bulk listen CB urb error, status: %d. Continuing.\n",
			urb->status);
		usb_submit_urb(urb, GFP_KERNEL);
		break;
	}
}

static int hss_read_cmd(struct usb_hss *dev)
{
	/* Start listening for commands */
	usb_fill_int_urb(dev->cmd_in_urb,
		dev->udev,
		usb_rcvintpipe(dev->udev,
			dev->cmd_in_endpointAddr),
		dev->cmd_in_buffer,
		sizeof(struct hss_packet),
		hss_read_cmd_callback,
		dev,
		dev->cmd_interval);
	dev->cmd_in_urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	usb_submit_urb(dev->cmd_in_urb, GFP_ATOMIC);

	/* Start listening for data */
	usb_fill_bulk_urb(dev->bulk_in_urb,
		dev->udev,
		usb_rcvbulkpipe(dev->udev,
			dev->bulk_in_endpointAddr),
		dev->bulk_in_buffer,
		XAPRC00X_BULK_IN_BUF_SIZE,
		hss_read_bulk_callback,
		dev);
	dev->bulk_in_urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	usb_submit_urb(dev->bulk_in_urb, GFP_ATOMIC);

	return 0;
}

/* Returns the ACK buf and lowers a semaphore to prevent concurrent access */
void *hss_get_ack_buf(struct usb_hss *dev)
{
	down(&dev->int_out_sem);
	return dev->cmd_out_buffer;
}

static void hss_cmd_out_callback(struct urb *urb)
{
	struct usb_hss *dev = urb->context;

	if (urb->status != 0)
		pr_info("Cmd failed status=%d", urb->status);

	up(&dev->int_out_sem);
}

int hss_cmd_out(void *context, void *msg, int msg_len)
{
	int ret;
	struct usb_hss *dev = context;

	usb_fill_int_urb(dev->cmd_out_urb,
		dev->udev,
		usb_sndintpipe(dev->udev,
			dev->cmd_out_endpointAddr),
		msg,
		msg_len,
		hss_cmd_out_callback,
		dev,
		dev->cmd_interval);
	dev->cmd_out_urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

	ret = usb_submit_urb(dev->cmd_out_urb, GFP_ATOMIC);

	return ret;
}

int hss_bulk_out(void *context, void *msg, int msg_len)
{
	int ret = -1;
	struct usb_hss *dev = context;
	int sent_len = 0;
	int actual_len = 0;

	/* Only one sock at a time */
	down(&dev->bulk_out_sem);

	while (sent_len != msg_len) {
		/* Send as much of the remaining message as possible */
		int seg_len = min(msg_len-sent_len, XAPRC00X_BULK_OUT_BUF_SIZE);

		memcpy(dev->bulk_out_buffer, ((char*)msg + sent_len), seg_len);

		/* Send a bulk message to the device and wait for a reply */
		ret = usb_bulk_msg(
			dev->udev,
			usb_sndbulkpipe(dev->udev,
				dev->bulk_out_endpointAddr),
			dev->bulk_out_buffer,
			seg_len,
			&actual_len,
			0);

		/* Increment the sent length if the call worked */
		if (ret == 0) {
			sent_len += actual_len;
		} else {
			break;
		}
	}

	up(&dev->bulk_out_sem);

	/* Either return the number of bytes sent or negative error code */
	return sent_len;
}

static void hss_driver_disconnect(struct usb_interface *interface)
{
	struct usb_hss *dev;

	dev = usb_get_intfdata(interface);
	usb_set_intfdata(interface, NULL);

	/* prevent more I/O from starting */
	dev->interface = NULL;

	/* decrement our usage count */
	kref_put(&dev->kref, hss_driver_delete);

	hss_proxy_destroy(dev->proxy_context);

	dev_info(&interface->dev, "HSS Driver now disconnected.");
}

/* Stop communicating when the host suspends */
static int hss_driver_suspend(struct usb_interface *intf,
	pm_message_t message)
{
	return 0;
}

static int hss_driver_resume(struct usb_interface *intf)
{
	return 0;
}

static int hss_driver_pre_reset(struct usb_interface *intf)
{
	return 0;
}

static int hss_driver_post_reset(struct usb_interface *intf)
{
	return 0;
}

static struct usb_driver hss_driver = {
	.name =		"hss",
	.probe =	hss_driver_probe,
	.disconnect =	hss_driver_disconnect,
	.suspend =	hss_driver_suspend,
	.resume =	hss_driver_resume,
	.pre_reset =	hss_driver_pre_reset,
	.post_reset =	hss_driver_post_reset,
	.id_table =	hss_device_table,
	.supports_autosuspend = 1,
};

module_usb_driver(hss_driver);

MODULE_LICENSE("GPL v2");
