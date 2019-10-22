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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef _XAPRC00X_BACKPORTS_H
#define _XAPRC00X_BACKPORTS_H

#include <linux/usb.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
int __must_check
usb_find_common_endpoints(struct usb_host_interface *alt,
                          struct usb_endpoint_descriptor **bulk_in,
                          struct usb_endpoint_descriptor **bulk_out,
                          struct usb_endpoint_descriptor **int_in,
                          struct usb_endpoint_descriptor **int_out);
#endif

#endif /* _XAPRC00X_BACKPORTS_H */
