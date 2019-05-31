obj-m += xarpcd.o 
WARN := -W -Wall
xarpcd-objs := xarpcd_main.o xarpcd_socket.o xarpcd_proxy.o xarpcd_usb.o psock_proxy_msg.o
CFLAGS := ${WARN}
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
