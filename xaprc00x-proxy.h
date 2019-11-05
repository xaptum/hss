/* SPDX-License-Identifier: GPL-2.0+ */
/**
 * @file xaprc00x-proxy.h
 * @brief External SCM proxy definitions
 */
#ifndef XAPRC00x_PROXY_H
#define XAPRC00x_PROXY_H

#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include "scm.h"

void xaprc00x_proxy_process_open(struct scm_packet *packet, u16 dev,
	struct scm_packet *ack);

void xaprc00x_proxy_process_cmd(struct scm_packet *packet, int packet_len,
	u16 dev, struct scm_packet *ack);

#endif