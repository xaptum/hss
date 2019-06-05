obj-m += xarpcd.o 
xarpcd-objs := xarpcd_main.o xarpcd_socket.o xarpcd_proxy.o xarpcd_usb.o psock_proxy_msg.o
ccflags-y := -DUSB_VENDOR_ID=$(USB_VENDOR_ID) -DUSB_PRODUCT_ID=$(USB_PRODUCT_ID) -DUSB_CLASS_ID=$(USB_CLASS_ID) -DUSB_SUBCLASS_ID=$(USB_SUBCLASS_ID) -DUSB_PROTO_ID=$(USB_PROTO_ID)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
