/**
 * @file xarpcd_main.c
 * @brief Main for the psock kernel module 
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


static int __init xarpcd_init(void)
{
	printk( KERN_INFO "xarpcd Init\n" );
	return 0;
}

static void __exit xarpcd_exit(void)
{
	printk( KERN_INFO "xarpcd Exit\n" );
}

//module_init( xarpcd_init );
//module_exit( xarpcd_exit );

