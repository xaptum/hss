/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * u_hss.h -- USB Host Socket Sharing (HSS) function driver
 *
 * Copyright (C) 2018-2019 Xaptum, Inc.
 */
#ifndef _U_HSS_H_
#define _U_HSS_H_

struct f_hss_opts {
	struct usb_function_instance func_inst;
	struct mutex lock;
	int refcnt;
};

#endif
