/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file hss_usb.h
 * @brief Implementation of the usb driver part for the xaptum tcp proxy
 *        Based of the usb-skeleton code
 */
#ifndef __XARPCD_USB_H_
#define __XARPCD_USB_H_

#define USB_VENDOR_ID_XAPTUM	 0x2fe0
#define USB_SUBCLASS_HSS_XAPTUM   0xab

struct usb_hss;
int hss_cmd_out(void *context, char *msg, int msg_len);
int hss_bulk_out(void *context, char *msg, int msg_len);
void *hss_get_ack_buf(struct usb_hss *dev);


#define XAPRC00X_BULK_IN_BUF_SIZE 1024
#define XAPRC00X_BULK_OUT_BUF_SIZE 1024

#endif
