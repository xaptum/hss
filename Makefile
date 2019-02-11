obj-m += xarpcd.o 
xarpcd-objs := xarpcd_main.o xarpcd_socket.o xarpcd_proxy.o xarpcd_usb.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
