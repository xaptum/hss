/**
 * Proxy part for the xarpcd kernel module
 */

#include "../../common/psock_proxy_msg.h"

#include "xarpcd_proxy.h"

#include <linux/printk.h>
#include <linux/net.h>
#include <net/sock.h>

#include <linux/circ_buf.h>

#include "xarpcd_socket.h"
#include "xarpcd_usb.h"

#define XARPCD_SUCCESS 1
#define XARPCD_FAIL 0

#define XARPCD_BUFFER_SIZE 16

#define XARPCD_PROXY_JIFFIES 100

static struct circ_buf *in_buffer;
static struct circ_buf *out_buffer;

struct xarpcd_buf_item
{
	void *msg;
};


static struct workqueue_struct *xarpcd_proxy_work_queue;
static struct delayed_work xarpcd_work;

void xarpcd_work_handle_msg( struct psock_proxy_msg *msg )
{
     printk( "Got a complete msg handling it\n" );
        if ( msg->type == F_PSOCK_MSG_ACTION_REQUEST )
        {

                switch ( msg->action )
                {
                        case F_PSOCK_CREATE:
                                // We want to create a socket
                                xarpcd_socket_create( msg->sock_id );
                                printk( "xarpcd_proxy : Socket creation successfull\n" );
                                break;
case F_PSOCK_CONNECT :
                                // We want to connect
                                printk( "xarpcd_proxy : Got a connection msg\n" );
                                {
                                        int result = -1;
                                        struct sockaddr *addr = msg->data;
                                        int addrlen = msg->length - sizeof( struct psock_proxy_msg );
                                        printk( "Connect request : sock %d, addrlen %d\n" , msg->sock_id, addrlen );
                                        result = xarpcd_socket_connect( msg->sock_id, addr, addrlen );

                                        // Creating the answer msg
                                        struct psock_proxy_msg *amsg = kmalloc( sizeof (struct psock_proxy_msg), GFP_KERNEL );
                                        amsg->length = sizeof( struct psock_proxy_msg );
                                        amsg->type = F_PSOCK_MSG_ACTION_REPLY;
                                        amsg->msg_id = msg->msg_id;
                                        amsg->sock_id = msg->sock_id;
                                        amsg->status = result;
                                        xarpcd_send_msg( amsg );        
                                }       
                                break;

				case F_PSOCK_READ :
				printk( "xarpcd_proxy : We got a read request\n" );
				{
					int result;
					int datalength = msg->status;
					printk( "xarpcd_proxy : reading %d bytes\n" , datalength );
					void *buf = kmalloc( datalength, GFP_KERNEL );
					result = xarpcd_socket_read( msg->sock_id, buf, datalength  );

                                        // Creating the answer msg
                                        struct psock_proxy_msg *amsg = kmalloc( sizeof (struct psock_proxy_msg), GFP_KERNEL );
                                        amsg->length = sizeof( struct psock_proxy_msg ) + datalength;
                                        amsg->type = F_PSOCK_MSG_ACTION_REPLY;
                                        amsg->msg_id = msg->msg_id;
                                        amsg->sock_id = msg->sock_id;
                                        amsg->status = result;
					msg->data = buf;
                                        xarpcd_send_msg( amsg );       

				}
                                break;
                        case F_PSOCK_WRITE :
                                // We want to write
				printk( "xarpcd_proxy : We got a write request\n" );
				{
					struct msghdr *hdr = kmalloc( sizeof( struct msghdr ), GFP_KERNEL );				int datalength = msg->length - sizeof( struct psock_proxy_msg );
					struct iovec *iov = kmalloc( sizeof(struct iovec ), GFP_KERNEL );
					int result;
					
					printk( "xarpcd_proxy : Writing %d bytes\n" , datalength );
					iov->iov_base = msg->data;
					iov->iov_len = datalength;
					
					iov_iter_init( &hdr->msg_iter, 0, iov, 1, datalength ); 
					result = xarpcd_socket_write( msg->sock_id, msg->data, datalength  );

                                        // Creating the answer msg
                                        struct psock_proxy_msg *amsg = kmalloc( sizeof (struct psock_proxy_msg), GFP_KERNEL );
                                        amsg->length = sizeof( struct psock_proxy_msg );
                                        amsg->type = F_PSOCK_MSG_ACTION_REPLY;
                                        amsg->msg_id = msg->msg_id;
                                        amsg->sock_id = msg->sock_id;
                                        amsg->status = result;
                                        xarpcd_send_msg( amsg );        
				}
                                break;
                        case F_PSOCK_CLOSE :
                                // We want to close the socket
                                break;

                        default :
                                break;
                }

        }
        else if ( msg->type == F_PSOCK_MSG_ACTION_REPLY  )
        {
                // Got an action reply
        }
        else if ( msg->type == F_PSOCK_MSG_NONE )
        {
                printk("Got a F_PSOCK_MSG_NONE msg .. ignoring it \n" );
        }

}

void xarpcd_work_handler( struct work_struct *work )
{
	struct psock_proxy_msg *msg;
	if ( xarpcd_proxy_pop_in_msg( (void **)&msg ) == XARPCD_SUCCESS )
	{
		xarpcd_work_handle_msg( msg );		
	}

	queue_delayed_work( xarpcd_proxy_work_queue, &xarpcd_work, XARPCD_PROXY_JIFFIES );
}

int xarpcd_proxy_init( void )
{
	in_buffer = kzalloc( sizeof(struct circ_buf), GFP_KERNEL );
	if ( in_buffer == NULL )
	{
		printk("Error allocating circ in_buffer\n" );
	}
	in_buffer->head = 0;
	in_buffer->tail = 0;

	in_buffer->buf = (char * ) kzalloc ( XARPCD_BUFFER_SIZE * sizeof(struct xarpcd_buf_item ) , GFP_KERNEL );

	if ( in_buffer->buf == NULL )
	{
		printk("Error allocating buff in in_buffer\n" );
	}	

	out_buffer = kzalloc( sizeof(struct circ_buf), GFP_KERNEL );
	if ( out_buffer == NULL )
	{
		printk("Eroor allocating circ out_buffer\n" );
	}
	out_buffer->head = 0;
	out_buffer->tail = 0;

	out_buffer->buf = (char *) kzalloc( XARPCD_BUFFER_SIZE * sizeof(struct xarpcd_buf_item ), GFP_KERNEL );
	
	if ( out_buffer->buf == NULL )
	{
		printk("Error allocating buff in out_buffer\n" );
	}

	// Setting up the work
	xarpcd_proxy_work_queue = create_workqueue( "xarpcd_proxy_work_queue" );
	INIT_DELAYED_WORK( &xarpcd_work, xarpcd_work_handler );
	queue_delayed_work( xarpcd_proxy_work_queue, &xarpcd_work, XARPCD_PROXY_JIFFIES );

	return XARPCD_SUCCESS;
}

int xparcd_proxy_cleanup( void )
{
	kfree( in_buffer->buf );
	kfree( out_buffer->buf );
	kfree( in_buffer );
	kfree( out_buffer );

	destroy_workqueue( xarpcd_proxy_work_queue );

	return XARPCD_SUCCESS;
}

/****************************************************************************
 * Api towards the socket handling code
 ***************************************************************************/

int xarpcd_proxy_pop_in_msg( void **msg )
{
	struct xarpcd_buf_item *item;
	unsigned long head = in_buffer->head;
	unsigned long tail = in_buffer->tail;

	if ( CIRC_CNT( head, tail, XARPCD_BUFFER_SIZE * sizeof( struct xarpcd_buf_item )) >= sizeof( struct xarpcd_buf_item ))
	{
		item = (struct xarpcd_buf_item *)(&in_buffer->buf[tail] );
		*msg = item->msg;

		in_buffer->tail = ( tail + sizeof( struct xarpcd_buf_item )) & ( XARPCD_BUFFER_SIZE * sizeof(struct xarpcd_buf_item ) -1 );

		return XARPCD_SUCCESS;
	}
	
	printk( "xarpcd in_buffer underflow\n" );
	return XARPCD_FAIL;
}

int xarpcd_proxy_push_out_msg( void *msg)
{
	struct xarpcd_buf_item *item;
	unsigned long head = out_buffer->head;
	unsigned long tail = out_buffer->tail;

	if ( CIRC_SPACE( head, tail, XARPCD_BUFFER_SIZE * sizeof( struct xarpcd_buf_item )) >= sizeof(struct xarpcd_buf_item ))
	{
		item = ( struct xarpcd_buf_item *)(&out_buffer->buf[head]);
		item->msg = msg;
		out_buffer->head = ( head + sizeof( struct xarpcd_buf_item )) & ( XARPCD_BUFFER_SIZE * sizeof( struct xarpcd_buf_item ) - 1 );
	}

	return XARPCD_SUCCESS;
}



/***************************************************************************
 * Api towards the usb handling code
 ***************************************************************************/

int xarpcd_proxy_pop_out_msg( void **msg )
{
	struct xarpcd_buf_item *item;
	unsigned long head = out_buffer->head;
	unsigned long tail = out_buffer->tail;

	if ( CIRC_CNT( head, tail, XARPCD_BUFFER_SIZE * sizeof( struct xarpcd_buf_item )) >= sizeof(struct xarpcd_buf_item ))
	{
		item = ( struct xarpcd_buf_item *) (&out_buffer->buf[tail] );
		*msg = item->msg;

		out_buffer->tail = ( tail + sizeof( struct xarpcd_buf_item )) & ( XARPCD_BUFFER_SIZE * sizeof( struct xarpcd_buf_item ) - 1 );

		return XARPCD_SUCCESS;
	}

	return XARPCD_FAIL;
}

int xarpcd_proxy_push_in_msg( void *msg )
{
	struct xarpcd_buf_item *item;

	unsigned long head = in_buffer->head;
	unsigned long tail = in_buffer->tail;

	if ( CIRC_SPACE( head, tail, XARPCD_BUFFER_SIZE * sizeof(struct xarpcd_buf_item )) >= sizeof(struct xarpcd_buf_item ) )
	{
		item = ( struct xarpcd_buf_item * )( &in_buffer->buf[head]);
		item->msg = msg;

		in_buffer->head = (head + sizeof( struct xarpcd_buf_item )) & ( XARPCD_BUFFER_SIZE * sizeof( struct xarpcd_buf_item ) - 1 );
		return XARPCD_SUCCESS;
	}
	
	return XARPCD_FAIL;	
}



int xarpcd_proxy_get_next_request( void )
{
	return 0;
}

int xarpcd_proxy_put_next_reply( void )
{
	return 0;
}

