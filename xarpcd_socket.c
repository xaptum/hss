/**
 * @file xarpcd_socket.c
 * @brief Socket handling from kernel space for the xaptum host driver
 * @author Jeroen Z
 */

#include <linux/net.h>
#include <linux/socket.h>

#include <net/sock.h>


/**
 * Create a socket
 */
static int xarpcd_socket_create( struct socket **sock )
{
	int r;

	r = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, sock);
	
	return r;
}

/**
 * Connect socket
 */
static int xarpcd_socket_connect( struct socket* sock , struct sockaddr * addr, int addrlen)
{
	return kernel_connect( sock, addr, addrlen, 0 ); 
}

/**
 * Write to socket
 */
static int xarpcd_socket_write( struct socket * sock, struct msghdr *msg )
{
	return sock_sendmsg( sock, msg );
}

/**
 * Read from socket
 */
static int xarpcd_socket_read( struct socket * sock, struct msghdr *msg )
{
	return sock_recvmsg( sock, msg , 0);
}

/**
 * Close the socket
 */
static int xarpcd_socket_close( struct socket *sock )
{
	sock_release( sock );
}
