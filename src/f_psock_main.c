/**
 * @file f_psock.c
 * @brief Main module part of the psock module 
 * @author Jeroen Z
 */

/**
 * @note At the moment for testing we directly load the module, 
 *       but this should be replace with the composite module laoding functions
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>

#include "f_psock_socket.h"
#include "f_psock_gadget.h"
#include "f_psock_proxy.h"


MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jeroen Z");
MODULE_DESCRIPTION("Xaptum tcp-proxy device kernel module");
MODULE_VERSION("0.0.1");


static int __init f_psock_init(void)
{
	printk( KERN_INFO "f_psock Init\n" );
	f_psock_init_sockets();
	f_psock_init_gadget();
	f_psock_proxy_init();
	return 0;
}

static void __exit f_psock_exit(void)
{
	printk( KERN_INFO "f_psock Exit\n" );
	f_psock_proxy_cleanup();
	f_psock_cleanup_gadget();
	f_psock_cleanup_sockets();
}


module_init( f_psock_init );
module_exit( f_psock_exit );


