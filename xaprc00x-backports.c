// SPDX-License-Identifier: GPL-2.0+
/*
 * XAP-RC-00x driver for Linux
 *
 *  Copyright (c) 2017-2019 Xaptum, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 */

#include <linux/module.h>

#include "xaprc00x-backports.h"

#if KERNEL_VERSION(4, 12, 0) > LINUX_VERSION_CODE
// Backported from the kernel source
static bool match_endpoint(struct usb_endpoint_descriptor *epd,
		struct usb_endpoint_descriptor **bulk_in,
		struct usb_endpoint_descriptor **bulk_out,
		struct usb_endpoint_descriptor **int_in,
		struct usb_endpoint_descriptor **int_out)
{
	switch (usb_endpoint_type(epd)) {
	case USB_ENDPOINT_XFER_BULK:
		if (usb_endpoint_dir_in(epd)) {
			if (bulk_in && !*bulk_in) {
				*bulk_in = epd;
				break;
			}
		} else {
			if (bulk_out && !*bulk_out) {
				*bulk_out = epd;
				break;
			}
		}

		return false;
	case USB_ENDPOINT_XFER_INT:
		if (usb_endpoint_dir_in(epd)) {
			if (int_in && !*int_in) {
				*int_in = epd;
				break;
			}
		} else {
			if (int_out && !*int_out) {
				*int_out = epd;
				break;
			}
		}

		return false;
	default:
		return false;
	}

	return (!bulk_in || *bulk_in) && (!bulk_out || *bulk_out) &&
			(!int_in || *int_in) && (!int_out || *int_out);
}

/**
 * usb_find_common_endpoints() -- look up common endpoint descriptors
 * @alt:	alternate setting to search
 * @bulk_in:	pointer to descriptor pointer, or NULL
 * @bulk_out:	pointer to descriptor pointer, or NULL
 * @int_in:	pointer to descriptor pointer, or NULL
 * @int_out:	pointer to descriptor pointer, or NULL
 *
 * Search the alternate setting's endpoint descriptors for the first bulk-in,
 * bulk-out, interrupt-in and interrupt-out endpoints and return them in the
 * provided pointers (unless they are NULL).
 *
 * If a requested endpoint is not found, the corresponding pointer is set to
 * NULL.
 *
 * Return: Zero if all requested descriptors were found, or -ENXIO otherwise.
 */
int usb_find_common_endpoints(struct usb_host_interface *alt,
			      struct usb_endpoint_descriptor **bulk_in,
			      struct usb_endpoint_descriptor **bulk_out,
			      struct usb_endpoint_descriptor **int_in,
			      struct usb_endpoint_descriptor **int_out)
{
	struct usb_endpoint_descriptor *epd;
	int i;

	if (bulk_in)
		*bulk_in = NULL;
	if (bulk_out)
		*bulk_out = NULL;
	if (int_in)
		*int_in = NULL;
	if (int_out)
		*int_out = NULL;

	for (i = 0; i < alt->desc.bNumEndpoints; ++i) {
		epd = &alt->endpoint[i].desc;

		if (match_endpoint(epd, bulk_in, bulk_out, int_in, int_out))
			return 0;
	}

	return -ENXIO;
}
#endif

MODULE_LICENSE("GPL");
