obj-m += f_psock.o 
f_psock-objs := f_psock_main.o f_psock_socket.o f_psock_proxy.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
