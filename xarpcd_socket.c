/**
 * @file xarpcd_socket.c
 * @brief Socket handling from kernel space for the xaptum host driver
 * 	  Sockets are stored locally in a list of all used sockets.
 * 	  The list is used for the mapping between the requested proxy socket_ids and the socket structs
 * @author Jeroen Z
 */

#include "xarpcd_socket.h"

#include "linux/preempt.h"

/**
 * Struct we use to store our local sockets in a list
 * So we can map the proxy socket ids, to local socket structs
 */
typedef struct xarpcd_socket
{
	int sock_id; 			/**< Internal proxy socket_id */
	struct socket *sock; 		/**< Pointer to the actual socket */
	struct list_head socket_list; 	/**< used for the linked list of sockets  */
} xarpcd_socket_t;

/**
 * The list of actual sockets
 */
LIST_HEAD( socket_list );

/**
 * Helper function to look for a socket base on its proxy socket_id
 */
static struct xarpcd_socket *xarpcd_get_xarpcd_socket( int socket_id )
{
	struct list_head *position = NULL;
	list_for_each( position, &socket_list )
	{
		xarpcd_socket_t *sock = list_entry( position, xarpcd_socket_t, socket_list );
		if ( sock->sock_id == socket_id )
		{
			printk("xarpcd_socket : found requested socket %d\n" , socket_id );
			return sock;
		}
	}
	return NULL;

}

/*******************************************************************************
 * Helper functions for working with the struct sockets directly 	       *
 ******************************************************************************/

/**
 * Create a socket
 */
int xarpcd_socket_create( int socket_id )
{
	int r;
	struct socket *sock;
	struct xarpcd_socket *psock;

	// First double check that we dont already have a socket with this socket_id
	if ( xarpcd_get_xarpcd_socket( socket_id ) != NULL )
	{
		printk( "xarpcd_socket : Request for creating socket %d failed ... already exists\n" , socket_id );
		return -1;
	}
	// Allocate our socket
	r = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if ( r < 0 )
	{
		printk( "xarpcd_socket : Error creating socket %d, result %d\n" , socket_id, r );
		return r;
	}

	// Create and initialize  our local socket struct
	psock = kmalloc( sizeof( struct xarpcd_socket ), GFP_KERNEL );
	psock->sock_id = socket_id;
	psock->sock = sock;

	// Add the socket to the list of sockets
	INIT_LIST_HEAD( &psock->socket_list );
	list_add( &psock->socket_list, &socket_list );

	printk( "xarpcd_socket : Successfully created socket %d\n" , socket_id );

	return r;
}

/**
 * Connect socket
 */
int xarpcd_socket_connect( int socket_id , struct sockaddr * addr, int addrlen)
{
	struct xarpcd_socket *sock = NULL;
	// Get the socket
	sock = xarpcd_get_xarpcd_socket( socket_id );

	if ( in_interrupt() )
	{
		printk("xarpcd_socket :  connect requested in interupt context ... bailing out\n" );
		return -1;
	}

	if ( sock == NULL )
	{
		printk( "xarpcd_socket : Trying to connect to unexisting socket %d\n" , socket_id );
		return -1;
	}

	// Doing the connect
	return kernel_connect( sock->sock, addr, addrlen, 0 ); 
}

/**
 * Write to socket
 */
int xarpcd_socket_write( int socket_id , struct msghdr *msg )
{
        struct xarpcd_socket *sock = NULL;
        // Get the socket
        sock = xarpcd_get_xarpcd_socket( socket_id );

        if ( sock == NULL )
        {
                printk( "xarpcd_socket : Trying to send data to unexisting socket %d\n" , socket_id );
                return -1;
        }

	return sock_sendmsg( sock->sock, msg );
}

/**
 * Read from socket
 */
int xarpcd_socket_read( int socket_id, struct msghdr *msg )
{
        struct xarpcd_socket *sock = NULL;
        // Get the socket
        sock = xarpcd_get_xarpcd_socket( socket_id );

        if ( sock == NULL )
        {
                printk( "xarpcd_socket : Trying to read from unexisting socket %d\n" , socket_id );
                return -1;
        }

	return sock_recvmsg( sock->sock, msg , 0);
}

/**
 * Close the socket
 **/
int xarpcd_socket_close( int socket_id )
{
	struct xarpcd_socket *sock = NULL;
        // Get the socket
        sock = xarpcd_get_xarpcd_socket( socket_id );

        if ( sock == NULL )
        {
                printk( "xarpcd_socket : Trying to realease an unexisting socket %d\n" , socket_id );
                return -1;
        }
	
	// Release the socket
	sock_release( sock->sock );
	sock->sock = NULL;

	// Remove the socket from the list
	list_del( &sock->socket_list );

	// Free the socket struct
	kfree( sock );

	printk( "xarpcd_socket : Successfully released socket %d\n" , socket_id );

	return 0;
}