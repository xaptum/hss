/**
 * @file xarpcd_socket.c
 * @brief Socket handling from kernel space for the xaptum host driver
 * @author Jeroen Z
 */

#include <linux/net.h>
#include <linux/socket.h>

#include <net/sock.h>



static int xarpcd_socket_create( void )
{
	int r;
	struct socket *control = NULL;

	r = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &control);
	
	return 0;
}

