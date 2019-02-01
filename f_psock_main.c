/**
 * @file f_psock.c
 * @brief 
 * @author Jeroen Z
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jeroen Z");
MODULE_DESCRIPTION("Xaptum tcp-proxy host kernel module");
MODULE_VERSION("0.0.1");


static int __init f_psock_init(void)
{
	printk( KERN_INFO "f_psock Init\n" );
	return 0;
}

static void __exit f_psock_exit(void)
{
	printk( KERN_INFO "f_psock Exit\n" );
}


module_init( f_psock_init );
module_exit( f_psock_exit );

