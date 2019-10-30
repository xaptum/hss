/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file xaprc00x_usb.c
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
#include <linux/mutex.h>

#include "xaprc00x-usb.h"
#include "xaprc00x-backports.h"

/* Match on vendor ID, interface class and interface subclass only. */
static const struct usb_device_id xaprc00x_device_table[] = {
	{ USB_VENDOR_AND_INTERFACE_INFO(
			USB_VENDOR_ID_XAPTUM,
			USB_CLASS_VENDOR_SPEC,
			USB_SUBCLASS_SCM_XAPTUM,
			USB_CDC_PROTO_NONE)
	}, { }
};
MODULE_DEVICE_TABLE(usb, xaprc00x_device_table);

/* Structure to hold all of our device specific stuff */
struct usb_xaprc00x {
	struct usb_device	*udev;
	struct usb_interface	*interface;
	__u8			bulk_in_endpointAddr;
	__u8			bulk_out_endpointAddr;
	__u8			cmd_in_endpointAddr;
	__u8			cmd_out_endpointAddr;
	struct kref		kref;
};

#define to_xaprc00x_dev(d) container_of(d, struct usb_xaprc00x, kref)

/********************************************************************
 * USB Driver Operations
 ********************************************************************/

static void xaprc00x_driver_delete(struct kref *kref)
{
	struct usb_xaprc00x *dev = to_xaprc00x_dev(kref);

	usb_put_dev(dev->udev);
	kfree(dev);
}

/**
 * xaprc00x_assign_endpoints - Find common bulk and int endpoints
 *
 * @dev The device to search
 *
 * Finds the first available in and out endpoints for both bulk and interrupt.
 *
 * Returns: 0 if all endpoints were matched, -ENXIO otherwise
 *
 */
static int xaprc00x_assign_endpoints(struct usb_xaprc00x *dev)
{
	struct usb_endpoint_descriptor *ep_in, *ep_out;
	struct usb_endpoint_descriptor *ep_cmd_in, *ep_cmd_out;
	int error;

	error = usb_find_common_endpoints(dev->interface->cur_altsetting,
			&ep_in, &ep_out, &ep_cmd_in, &ep_cmd_out);

	if (!error) {
		/* Store the endpoint addresses */
		dev->bulk_in_endpointAddr = ep_in->bEndpointAddress;
		dev->bulk_out_endpointAddr = ep_out->bEndpointAddress;
		dev->cmd_out_endpointAddr = ep_cmd_out->bEndpointAddress;
		dev->cmd_in_endpointAddr = ep_cmd_in->bEndpointAddress;
	} else {
		dev_err(&dev->interface->dev,
			"Could not find all endpoints\n");
	}

	return error;
}

/**
 * Probe function called when device with correct vendor / productid is found
 */
static int xaprc00x_driver_probe(struct usb_interface *interface,
			const struct usb_device_id *id)
{
	struct usb_xaprc00x *dev;
	int retval = 0;

	/* Allocate and initialize the device */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	kref_init(&dev->kref);

	dev->udev = usb_get_dev(interface_to_usbdev(interface));
	dev->interface = interface;

	/* Set up the bulk and interrupt endpoints */
	retval = xaprc00x_assign_endpoints(dev);
	if (retval)
		goto error;

	/* Tell the USB interface where our device data is located */
	usb_set_intfdata(interface, dev);

	/* let the user know what node this device is now attached to */
	dev_info(&interface->dev, "SCM Driver now attached.");

error:
	if (retval)
		kref_put(&dev->kref, xaprc00x_driver_delete);

	return retval;
}

static void xaprc00x_driver_disconnect(struct usb_interface *interface)
{
	struct usb_xaprc00x *dev;

	dev = usb_get_intfdata(interface);
	usb_set_intfdata(interface, NULL);

	/* prevent more I/O from starting */
	dev->interface = NULL;

	/* decrement our usage count */
	kref_put(&dev->kref, xaprc00x_driver_delete);

	dev_info(&interface->dev, "SCM Driver now disconnected.");
}

/* Stop communicating when the host suspends */
static int xaprc00x_driver_suspend(struct usb_interface *intf,
	pm_message_t message)
{
	return 0;
}

static int xaprc00x_driver_resume(struct usb_interface *intf)
{
	return 0;
}

static int xaprc00x_driver_pre_reset(struct usb_interface *intf)
{
	return 0;
}

static int xaprc00x_driver_post_reset(struct usb_interface *intf)
{
	return 0;
}

static struct usb_driver xaprc00x_driver = {
	.name =		"xaprc00x",
	.probe =	xaprc00x_driver_probe,
	.disconnect =	xaprc00x_driver_disconnect,
	.suspend =	xaprc00x_driver_suspend,
	.resume =	xaprc00x_driver_resume,
	.pre_reset =	xaprc00x_driver_pre_reset,
	.post_reset =	xaprc00x_driver_post_reset,
	.id_table =	xaprc00x_device_table,
	.supports_autosuspend = 1,
};

module_usb_driver(xaprc00x_driver);

MODULE_LICENSE("GPL v2");
