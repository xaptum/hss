/**
 * @file f_psock_proxy.c 
 * @brief Implementation for the Proxying of the sockets
 */

#include "f_psock_proxy.h"
#include "psock_proxy_msg.h"

#include <linux/circ_buf.h>
#include <linux/printk.h>
#include <linux/net.h>

#include <net/sock.h>

#define F_PSOCK_PROXY_JIFFIES 50
#define F_PSOCK_MSG_TIMEOUT 10000
#define F_PSOCK_MAX_MSG_WORK	5 

// Note this should be a multiple of 2!!
// Is the amount of msg the buffer can hold
#define F_PSOCK_BUFF_SIZE 16

// Forward declarations
static int f_psock_proxy_push_out_msg( void *msg );
int f_psock_proxy_pop_in_msg( void ** msg );
int f_psock_proxy_wait_send( psock_proxy_msg_t *msg );

// Lets keep track of the number of sockets (Used for local socket_id )
static int sock_counter = 0;
// Lets also keep track of the msg, so we can have a unique id for all msgs
static int msg_counter = 0;

// List of msgs waiting for an answer
LIST_HEAD( wait_list );

/**
 * Function to find a msg on the wait list
 */
static psock_proxy_msg_t *wait_list_get_msg_id( int id )
{
	struct list_head *position = NULL;
	list_for_each( position, &wait_list )
	{
		psock_proxy_msg_t *msg = list_entry( position, psock_proxy_msg_t, wait_list );
		if ( msg->msg_id == id )
		{
			return msg;
		}
	}
	return NULL;
}

/**
 * Wait queue where we park action msgs that are sent, until we have a reply
 * msg->state == MSG_ANSWERED
 * or until msg sent if we dont care about the reply
 */
static wait_queue_head_t f_psock_proxy_wait_queue;

// Worker that periodically checks the wait queue
static struct workqueue_struct *f_psock_proxy_work_queue;
static struct delayed_work f_psock_work; 

void f_psock_proxy_handle_in_msg( struct psock_proxy_msg *msg )
{
	printk( KERN_INFO "f_psock_proxy: Got an incomming msg\n" );
	if ( msg->type == F_PSOCK_MSG_ACTION_REPLY )
	{
		struct psock_proxy_msg *orig = wait_list_get_msg_id( msg->msg_id );
		if ( orig != NULL )
		{
			orig->related = msg;
			orig->state = MSG_ANSWERED;
		}
		else
		{
			printk( "f_psock_proxy: Could not find original msg_id :%d\n", msg->msg_id);
		}
	}

}

// Work queue function
void f_psock_work_handler( struct work_struct *work )
{
	struct psock_proxy_msg *msg;
	int count = 0;
	// Handle pending incoming msg's 
	while( (f_psock_proxy_pop_in_msg( (void **)&msg  ) == F_PSOCK_SUCCESS ) 
	       && ( count < F_PSOCK_MAX_MSG_WORK ) )
	{
		f_psock_proxy_handle_in_msg( msg );
		count++;
	}
	
	// Wake up the msgs that got an answer
	wake_up( &f_psock_proxy_wait_queue );

	// Requeue the task
	queue_delayed_work( f_psock_proxy_work_queue, &f_psock_work, F_PSOCK_PROXY_JIFFIES );
}

/**
 * Use this buffer to buffer incoming msgs from the usb stack
 */
static struct circ_buf *in_buffer;

/**
 * Use this buffer to send msgs to the usb stack
 */
static struct circ_buf *out_buffer;

/**
 * Item for in the circular buffers
 */
struct psock_buf_item
{
	void *msg;
};

/**
 * Function creates the in_buffer
 */
static int f_psock_proxy_create_in_buffer( void )
{
	// Create the in_buffer
	in_buffer = kzalloc( sizeof(struct circ_buf), GFP_KERNEL );
	if ( in_buffer == NULL )
	{
		printk("Error allocating circ in_buffer\n" );
	}
	in_buffer->head = 0;
	in_buffer->tail = 0;

	in_buffer->buf = (char * ) kzalloc( F_PSOCK_BUFF_SIZE* sizeof(struct psock_buf_item ) , GFP_KERNEL);

	if ( in_buffer->buf == NULL )
	{
		printk("Error allcating buff in in_buffer\n" );
	}

	return F_PSOCK_SUCCESS;


}

/**
 * Functio creates the out_buffer
 */
static int f_psock_proxy_create_out_buffer( void )
{

	// Create the out_buffer
	out_buffer = kzalloc( sizeof(struct circ_buf), GFP_KERNEL );
	if ( out_buffer == NULL )
	{
		printk("Error allocating circ out_buffer\n" );
	}	
	out_buffer->head = 0;
	out_buffer->tail = 0;

	out_buffer->buf = (char *) kzalloc( F_PSOCK_BUFF_SIZE* sizeof(struct psock_buf_item) , GFP_KERNEL );

	if ( out_buffer->buf == NULL )
	{
		printk("Error allocating buff in out_buffer\n" );
	}

	return F_PSOCK_SUCCESS;
}


/**
 * Initialize the proxy
 */
int f_psock_proxy_init( void )
{
	// Waitqueue initialization
	init_waitqueue_head( & f_psock_proxy_wait_queue );

 	// Initialize the buffers
	f_psock_proxy_create_in_buffer();
	f_psock_proxy_create_out_buffer();

	// Work and workqueue initialization
	f_psock_proxy_work_queue = create_workqueue( "f_psock_proxy_work_queue" );
	INIT_DELAYED_WORK( &f_psock_work, f_psock_work_handler );
	queue_delayed_work( f_psock_proxy_work_queue, &f_psock_work, F_PSOCK_PROXY_JIFFIES );

	return F_PSOCK_SUCCESS;
}



/** 
 * Cleanup the proxy
 */
int f_psock_proxy_cleanup( void )
{
	//@todo we should pop our message first so we can  the msgs also
	
	kfree( in_buffer->buf );
	kfree( out_buffer->buf );
	kfree( in_buffer );
	kfree( out_buffer );

	destroy_workqueue( f_psock_proxy_work_queue );
	// @todo destroy the waitqueue

	return F_PSOCK_SUCCESS;
}

/***************************************************************
 * Socket side api
 **************************************************************/
/**
 * Here we create a create socket msg and put in on the queue to be sent over usb.
 */
int f_psock_proxy_create_socket( f_psock_proxy_socket_t *psk )
{
	psock_proxy_msg_t * msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);
	if ( !msg )
	{
		printk( KERN_ERR "psock_proxy: Error allocating memory for create msg\n" );
		return F_PSOCK_FAIL; 
	}

	msg->magic = PSOCK_MSG_MAGIC;	
	msg->type = F_PSOCK_MSG_ACTION_REQUEST;
	msg->action = F_PSOCK_CREATE,
	msg->msg_id = msg_counter++;
	msg->sock_id = sock_counter++;
	msg->length = sizeof(struct psock_proxy_msg );
	msg->data = NULL;

	msg->state = MSG_PENDING; 
	msg->related = NULL;

	psk->local_id = msg->sock_id;

	f_psock_proxy_push_out_msg( msg );

	f_psock_proxy_wait_send( msg );

	printk( KERN_INFO "psock_proxy: Created socket with id : %d\n" , msg->sock_id);

	// Free the msg
	kfree( msg );

	return psk->local_id;
}

/**
 * Delete / close a socket and send close msg to the host
 */
int f_psock_proxy_delete_socket( f_psock_proxy_socket_t *psk )
{

        psock_proxy_msg_t * msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);

	printk( "f_psock_proxy_delete_socket\n" );
       
       	msg->magic = PSOCK_MSG_MAGIC;	
	msg->type = F_PSOCK_MSG_ACTION_REQUEST;
        msg->action = F_PSOCK_CLOSE;
	msg->msg_id = msg_counter++;
        msg->sock_id = psk->local_id;
        msg->length = sizeof( struct psock_proxy_msg );
        msg->data = NULL;

	msg->state = MSG_PENDING;
	msg->related = NULL;

        f_psock_proxy_push_out_msg( msg );
	
	f_psock_proxy_wait_send( msg );

	kfree( msg );

	return 0;
}

/**
 * Function waits until we have an incomming answer msg
 */
int f_psock_proxy_wait_answer( psock_proxy_msg_t *msg, psock_proxy_msg_t  **answermsg )
{
	int res = -1;
	printk( "Waiting for answer to socket msg %d\n", msg->msg_id );

	// Add the msg to the list of waiting for an answer msgs
	INIT_LIST_HEAD( &msg->wait_list );
	list_add( &msg->wait_list, &wait_list );	

	wait_event_timeout( f_psock_proxy_wait_queue, ( msg->state == MSG_ANSWERED ), F_PSOCK_MSG_TIMEOUT );

	if ( msg->state == MSG_ANSWERED )
	{
		printk( "Got an answer for socket msg\n" );
		// Handle the result
		*answermsg = msg->related;
		res = 1;
	}
	else 
	{
		printk( KERN_ERR "psock_proxy: Got a timeout waiting for msg answer\n" );
	}

	// We can remove the item from the list now
	list_del( &msg->wait_list );

	return res;
}

/**
 * Function wait until a msg has been sent
 */
int f_psock_proxy_wait_send( psock_proxy_msg_t *msg )
{
	int res = F_PSOCK_FAIL;
	printk( "psock_proxy : Waiting for send socket msg %d\n", msg->msg_id );

	// Add the msg to the list of waiting for an answer msgs
	INIT_LIST_HEAD( &msg->wait_list );
	list_add( &msg->wait_list, &wait_list );	

	wait_event_timeout( f_psock_proxy_wait_queue, ( msg->state == MSG_SEND ), F_PSOCK_MSG_TIMEOUT );
	if ( msg->state == MSG_SEND )
	{
		res = F_PSOCK_SUCCESS;
	}
	else
	{
		printk( KERN_ERR "Wait send timeout, should not happen\n" );
	}

	// We can remove the item from the list now
	list_del( &msg->wait_list );

	return res;

}

/**
 * Connect the socket to a remote address
 */
int f_psock_proxy_connect_socket( f_psock_proxy_socket_t *psk, struct sockaddr *addr, int alen )
{
	int result = F_PSOCK_FAIL;
	psock_proxy_msg_t * msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);
	psock_proxy_msg_t * answer;

	printk( "f_psock_proxy_connect_socket\n" );
       
        msg->magic = PSOCK_MSG_MAGIC;	
	msg->type = F_PSOCK_MSG_ACTION_REQUEST;
        msg->action = F_PSOCK_CONNECT,
	msg->msg_id = msg_counter++;
        msg->sock_id = psk->local_id;
        msg->length = alen + sizeof( psock_proxy_msg_t );
        msg->data = kzalloc( alen, GFP_KERNEL );
	memcpy( msg->data, addr, alen );
	
	msg->state = MSG_PENDING;
	msg->related = NULL;

	// Lets push the msg on the out queus
        f_psock_proxy_push_out_msg( msg );

	// Now we need to wait for a reply
	if ( f_psock_proxy_wait_answer( msg, &answer ) > 0 )
	{
		printk( "Got a correct answer\n" );
		result =  answer->status;
		kfree ( answer );
	};

	kfree( msg );
	printk( "Got an timeout for answer\n" );
	return result;
}

/**
 * Write data to the socket, will send a msg to the host with the data in it, so it can be written to the socket there
 * As long as the proxy out buffer is not full we assume we can write
 * @todo do length check (dont want it to be too big )
 * @todo check full buffer
 */
int f_psock_proxy_write_socket( f_psock_proxy_socket_t *psk, void *data, size_t len )
{
	int result = F_PSOCK_FAIL;
	psock_proxy_msg_t * msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);
 	psock_proxy_msg_t * answer;

	printk( "f_psock_proxy_write_socket %d %ld\n", psk->local_id, len );

	msg->magic = PSOCK_MSG_MAGIC;
        msg->type = F_PSOCK_MSG_ACTION_REQUEST;
        msg->action = F_PSOCK_WRITE,
	msg->msg_id = msg_counter++;
        msg->sock_id = psk->local_id;
        msg->length = len + sizeof( psock_proxy_msg_t );
        msg->data = data;

	msg->state = MSG_PENDING;
	msg->related = NULL;

        f_psock_proxy_push_out_msg( msg );

        // Now we need to wait for a reply
        if ( f_psock_proxy_wait_answer( msg, &answer ) > 0 )
        {       
                result =  answer->status;
		kfree( answer );
        };

	kfree( msg );
        return result;

}

/**
 * Read incoming data, if no data available yet, just returns
 * @todo check if we want to support blocking
 */
int f_psock_proxy_read_socket( f_psock_proxy_socket_t *psk, void *data, size_t len )
{
	int result = F_PSOCK_FAIL;
	psock_proxy_msg_t * msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);
 	psock_proxy_msg_t * answer;

	printk( "f_psock_proxy_read_socket %d %ld\n", psk->local_id, len );

	msg->magic = PSOCK_MSG_MAGIC;
        msg->type = F_PSOCK_MSG_ACTION_REQUEST;
        msg->action = F_PSOCK_READ,
	msg->msg_id = msg_counter++;
        msg->sock_id = psk->local_id;
        msg->length = sizeof( psock_proxy_msg_t );
        msg->data = NULL;
	msg->status = len;
	msg->state = MSG_PENDING;
	msg->related = NULL;

        f_psock_proxy_push_out_msg( msg );

        // Now we need to wait for a reply
        if ( f_psock_proxy_wait_answer( msg, &answer ) > 0 )
        {       
                printk( "f_psock_proxy: read_socket: Got a correct answer read :%d\n", answer->status );
		memcpy( data, answer->data, answer->status );
		result = answer->status;
		kfree( answer->data );
		kfree( answer );
        }

	kfree( msg );
        
	return result;

}

/**
 * Functions pushes a msg on the out buffer
 */
static int f_psock_proxy_push_out_msg( void *msg )
{
	struct psock_buf_item *item;
	unsigned long head = out_buffer->head;
	unsigned long tail = out_buffer->tail;

 	if ( CIRC_SPACE( head, tail, F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item )) >= sizeof(struct psock_buf_item ) )
	{
		item = ( struct psock_buf_item *)(&out_buffer->buf[head]);
		// Setup item
		item->msg = msg;	
		// Update head
		out_buffer->head = (head + sizeof( struct psock_buf_item )) & ( F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item )  - 1 );

		return F_PSOCK_SUCCESS;
	}

	return F_PSOCK_FAIL;

}

/**
 * Function to pop a msg from the in buffer
 */
int f_psock_proxy_pop_in_msg( void ** msg )
{

	struct psock_buf_item *item;
	unsigned long head = in_buffer->head;
	unsigned long tail = in_buffer->tail;
	
	if ( CIRC_CNT( head, tail, F_PSOCK_BUFF_SIZE*sizeof(struct psock_buf_item )) >= sizeof(struct psock_buf_item ) )
	{
		item = (struct psock_buf_item *)(&in_buffer->buf[tail]);
		
		*msg = item->msg;

		in_buffer->tail = (tail + sizeof( struct psock_buf_item )) & ( F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item ) - 1 ); 
	
		return F_PSOCK_SUCCESS;
	}

	return F_PSOCK_FAIL;

}


/**************************************************************
 * Usb communication side api
 *************************************************************/

/**
 * Function to pop a msg from the out buffer
 */
int f_psock_proxy_pop_out_msg( void ** msg )
{

	struct psock_buf_item *item;
	unsigned long head = out_buffer->head;
	unsigned long tail = out_buffer->tail;

	 if ( CIRC_CNT( head, tail, F_PSOCK_BUFF_SIZE*sizeof(struct psock_buf_item )) >= sizeof(struct psock_buf_item ) )
	{
		item = (struct psock_buf_item *)(&out_buffer->buf[tail]);

		*msg = item->msg;

		out_buffer->tail = (tail + sizeof( struct psock_buf_item )) & ( F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item ) - 1 );


		return F_PSOCK_SUCCESS;
	}


	return F_PSOCK_FAIL;
}

/**
 * Function to push a msg to the in buffer
 */
int f_psock_proxy_push_in_msg( void * msg)
{

	struct psock_buf_item *item;

	unsigned long head = in_buffer->head;
	unsigned long tail = in_buffer->tail; 

	if ( CIRC_SPACE( head, tail, F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item )) >= sizeof(struct psock_buf_item ) ) 
	{
		item = ( struct psock_buf_item *)(&in_buffer->buf[head]);
		// Setup item
	
		item->msg = msg;
		// Update head
		in_buffer->head = (head + sizeof( struct psock_buf_item )) & ( F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item ) - 1 );	
		
		return F_PSOCK_SUCCESS;
	}


	return F_PSOCK_FAIL;

}

