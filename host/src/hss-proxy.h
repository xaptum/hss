/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file hss-proxy.h
 * @brief External HSS proxy definitions
 */
#ifndef XAPRC00x_PROXY_H
#define XAPRC00x_PROXY_H

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include "hss.h"

void *hss_proxy_init(void *context);

void hss_proxy_rcv_cmd(char *packet,
	int packet_len, void *context);

int hss_proxy_rcv_data(void *data, int len, void *context);

void hss_proxy_destroy(void *context);
#endif
