
#ifndef __XARPCD_USB_H_
#define __XARPCD_USB_H_

#include "psock_proxy_msg.h"


/* Define these values to match your devices */
#define USB_VENDOR_ID_XAPRW001	 0x02fe
#define USB_PRODUCT_ID_XAPRW001	 0x0b02
#define USB_CLASS_ID_XAPRW001 	 0xFF
#define USB_SUBCLASS_ID_XAPRW001 0xAB
#define USB_PROTO_ID_XAPRW001	 0x00


int xarpcd_send_msg( struct psock_proxy_msg *msg );

#endif 
