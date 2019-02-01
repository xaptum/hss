/**
 *
 *
 *
 */

#include <linux/net.h>
#include <linux/socket.h>

#include <net/sock.h>



static int f_psock_socket_create( void )
{
	int r;
	struct socket *control = NULL;

	r = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &control);
	
	return 0;
}
