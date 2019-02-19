/**
 * Proxy part for the xarpcd kernel module
 */

#include "../../common/psock_proxy_msg.h"

#include <linux/printk.h>
#include <linux/net.h>
#include <net/sock.h>

#include <linux/circ_buf.h>

#define XARPCD_SUCCESS 1
#define XARPCD_FAIL 0

#define XARPCD_BUFFER_SIZE 16

static struct circ_buf *in_buffer;
static struct circ_buf *out_buffer;

struct xarpcd_buf_item
{
	void *msg;
};


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
	
	return XARPCD_SUCCESS;
}

int xparcd_proxy_cleanup( void )
{
	kfree( in_buffer->buf );
	kfree( out_buffer->buf );
	kfree( in_buffer );
	kfree( out_buffer );

	return XARPCD_SUCCESS;
}

/****************************************************************************
 * Api towards the usb handling code
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
 * Api towards the socket handling code
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

