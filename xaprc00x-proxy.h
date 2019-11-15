/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file xaprc00x-proxy.h
 * @brief External SCM proxy definitions
 */
#ifndef XAPRC00x_PROXY_H
#define XAPRC00x_PROXY_H

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include "scm.h"

void xaprc00x_proxy_process_cmd(struct work_struct *work);

struct workqueue_struct *xaprc00x_proxy_init(int dev, void *context);

void xaprc00x_proxy_rcv_cmd(struct workqueue_struct *wq,
	struct scm_packet *packet, int packet_len, u16 dev, void *context);

void xaprc00x_proxy_destroy(struct workqueue_struct *wq);
#endif