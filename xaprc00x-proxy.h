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

void *xaprc00x_proxy_init(void *context);

void xaprc00x_proxy_rcv_cmd(struct scm_packet *packet,
	int packet_len, void *context);

int xaprc00x_proxy_rcv_data(void *data, int len, void *context);

void xaprc00x_proxy_destroy(void *context);
#endif
