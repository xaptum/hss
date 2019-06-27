
#ifndef __XARPCD_USB_H_
#define __XARPCD_USB_H_

#include "psock_proxy_msg.h"

/* Define these values to match your devices */
#define USB_VENDOR_ID_XAPTUM	 0x2fe0
#define USB_SUBCLASS_XAPTUM_PSOCK   0xab

int xarpcd_send_msg( struct psock_proxy_msg *msg );

#endif 
