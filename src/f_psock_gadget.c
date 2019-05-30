/**
 * @file f_psock_gadget.c
 * @brief Usb gadget / composite framework integration for the f_psock kernel module
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>

#include <linux/usb/composite.h>

#include "psock_proxy_msg.h"
#include "f_psock_proxy.h"

#define PSOCK_PROXY_JIFFIES 50
#define PSOCK_GADGET_MAX_SEND 5
#define PSOCK_GADGET_BUF_SIZE 512

/**************************************************************************
 *  f_psock structure definitions
 **************************************************************************/

/**
 * Usb function instance structure definition
 */
struct f_psock_opts {
	struct usb_function_instance func_inst;

	unsigned bulk_buflen;
	unsigned qlen;

	struct mutex lock;
	int refcnt;
};

/**
 * Usb function structure definition
 */
struct f_psock {
	struct usb_function     function;

        struct usb_ep           *in_ep;
        struct usb_ep           *out_ep;

        unsigned                qlen;
        unsigned                buflen;
	

};

/**
 * Forward declarations
 */
static int alloc_msg_send_request( struct usb_composite_dev *cdev, struct f_psock *psock, struct psock_proxy_msg *msg );
static int alloc_msg_read_request( struct usb_composite_dev *cdev, struct f_psock *psock );


/**************************************************************************
 * Workqueue and related
 **************************************************************************/
static struct workqueue_struct *f_psock_gadget_work_queue;
static struct delayed_work f_psock_gadget_work;

// @todo check for better way to keep this info as this makes it impossible to use more then one instnace
static struct usb_composite_dev *w_cdev;
static struct f_psock *w_psock; 

void f_psock_gadget_work_handler( struct work_struct *work )
{
	printk("f_psock: f_psock_gadget_work_handler enter");
	int count = 0;
	psock_proxy_msg_t * msg = NULL;
	
	// Check if we have new outgoing msg to send
	while ( ( f_psock_proxy_pop_out_msg( (void **)&msg ) == 1 )
	     && ( count < PSOCK_GADGET_MAX_SEND ) )
	{
		alloc_msg_send_request( w_cdev, w_psock, msg );	
		count++;	
	}	


	// Requeue the task
	queue_delayed_work( f_psock_gadget_work_queue, &f_psock_gadget_work, PSOCK_PROXY_JIFFIES );
}



/***************************************************************************
 * USB DESCRIPTOR DEFINITIONS
 ***************************************************************************/

/*
 * usb interface descriptor
 */
static struct usb_interface_descriptor psock_intf = {
	.bLength = sizeof(psock_intf),
	.bDescriptorType = USB_DT_INTERFACE,
	.bNumEndpoints = 2,
	.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass = 0xab,
};

/**
 * Full speed endpoint descriptors
 */
static struct usb_endpoint_descriptor fs_psock_source_desc =  {
	.bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bEndpointAddress =     USB_DIR_IN,
        .bmAttributes =         USB_ENDPOINT_XFER_BULK,


};


static struct usb_endpoint_descriptor fs_psock_sink_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bEndpointAddress =     USB_DIR_OUT,
        .bmAttributes =         USB_ENDPOINT_XFER_BULK,

};

static struct usb_descriptor_header *fs_psock_descs[] = {
 	(struct usb_descriptor_header *) &psock_intf,
        (struct usb_descriptor_header *) &fs_psock_sink_desc,
        (struct usb_descriptor_header *) &fs_psock_source_desc,
        NULL,
};

/**
 * High speed descriptors
 */
static struct usb_endpoint_descriptor hs_psock_source_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_psock_sink_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_descriptor_header *hs_psock_descs[] = {
        (struct usb_descriptor_header *) &psock_intf,
        (struct usb_descriptor_header *) &hs_psock_source_desc,
        (struct usb_descriptor_header *) &hs_psock_sink_desc,
        NULL,
};

/**
 * Superspeed descriptors
 */
static struct usb_endpoint_descriptor ss_psock_source_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_psock_source_comp_desc = {
        .bLength =              USB_DT_SS_EP_COMP_SIZE,
        .bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
        .bMaxBurst =            0,
        .bmAttributes =         0,
        .wBytesPerInterval =    0,
};

static struct usb_endpoint_descriptor ss_psock_sink_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_psock_sink_comp_desc = {
        .bLength =              USB_DT_SS_EP_COMP_SIZE,
        .bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
        .bMaxBurst =            0,
        .bmAttributes =         0,
        .wBytesPerInterval =    0,
};

static struct usb_descriptor_header *ss_psock_descs[] = {
        (struct usb_descriptor_header *) &psock_intf,
        (struct usb_descriptor_header *) &ss_psock_source_desc,
        (struct usb_descriptor_header *) &ss_psock_source_comp_desc,
        (struct usb_descriptor_header *) &ss_psock_sink_desc,
        (struct usb_descriptor_header *) &ss_psock_sink_comp_desc,
        NULL,
};

/**
 * USB string definitions
 */ 
static struct usb_string strings_psock[] = {
        [0].s = "psock interface",
        {  }                    /* end of list */
};

static struct usb_gadget_strings stringtab_psock = {
        .language       = 0x0409,       /* en-us */
        .strings        = strings_psock,
};

static struct usb_gadget_strings *psock_strings[] = {
        &stringtab_psock,
        NULL,
};


/**********************************************************************
 *
 **********************************************************************/


/**
 * usb allocation
 */

static inline struct f_psock *func_to_psock(struct usb_function *f)
{
        return container_of(f, struct f_psock, function);
}


static int psock_bind( struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct f_psock *psock = func_to_psock(f);
	int id;
	int ret;

	id = usb_interface_id(c,f);
	if (id < 0 )
	{
		return id;
	}
	psock_intf.bInterfaceNumber = id;

	id = usb_string_id(cdev);
	if (id < 0 ) return id;


	strings_psock[0].id = id;
	psock_intf.iInterface = id;

	psock->in_ep = usb_ep_autoconfig(cdev->gadget, &fs_psock_source_desc );
	if (!psock->in_ep) {
	        ERROR(cdev, "%s: can't autoconfigure on %s\n",
                        f->name, cdev->gadget->name);
                return -ENODEV;

	}

	psock->out_ep = usb_ep_autoconfig(cdev->gadget, &fs_psock_sink_desc );
	if (!psock->out_ep)
	{
		ERROR(cdev, "%s: can't autoconfigure on %s\n",
                        f->name, cdev->gadget->name);
                return -ENODEV;

	}

	/* support high speed hardware */
        hs_psock_source_desc.bEndpointAddress =
                fs_psock_source_desc.bEndpointAddress;
        hs_psock_sink_desc.bEndpointAddress = fs_psock_sink_desc.bEndpointAddress;

        /* support super speed hardware */
        ss_psock_source_desc.bEndpointAddress =
                fs_psock_source_desc.bEndpointAddress;
        ss_psock_sink_desc.bEndpointAddress = fs_psock_sink_desc.bEndpointAddress;

 	ret = usb_assign_descriptors(f, fs_psock_descs, hs_psock_descs,
                        ss_psock_descs, NULL);


	return ret;
}

static void psock_free_func( struct usb_function *f )
{
	struct f_psock_opts *opts;

	printk( "f_psock: psock_free_func\n" );

        opts = container_of(f->fi, struct f_psock_opts, func_inst);

        mutex_lock(&opts->lock);
        opts->refcnt--;
        mutex_unlock(&opts->lock);

        usb_free_all_descriptors(f);
        kfree(func_to_psock(f));
	
}

static int enable_endpoint( struct usb_composite_dev *cdev, struct f_psock *psock, struct usb_ep *ep )
{
	int result;
	result = config_ep_by_speed( cdev->gadget, &(psock->function), ep );

	result = usb_ep_enable(ep);

	ep->driver_data = psock;

	result = 0;

	return result;
}


static void psock_send_complete( struct usb_ep *ep, struct usb_request *req )
{
	struct psock_proxy_msg *msg = req->context;
	if ( msg != NULL )
	{
		msg->state = MSG_SEND;
	}
	printk( "psock_gadget: completed sending msg\n" );
}


static void psock_read_complete( struct usb_ep *ep, struct usb_request *req )
{

	// Push the msg to the proxy
	psock_proxy_msg_packet_t *packet = req->buf;
	psock_proxy_msg_t *msg = kmalloc( sizeof( struct psock_proxy_msg ) , GFP_KERNEL );
	uint32_t packet_len = 0;

	packet_len = psock_proxy_packet_to_msg(packet,msg);

	printk( "Msg : %d %d %u\n", msg->type, msg->msg_id, msg->length );

	if ( msg->length > req->length )
	{
		printk( KERN_ERR "Incomplete msg received\n" );
	}

	if ( msg->length > sizeof( psock_proxy_msg_t ) )
	{
		msg->data = kmalloc( msg->length - sizeof( psock_proxy_msg_t ), GFP_KERNEL );
		memcpy( msg->data,  packet->data , msg->length - sizeof(psock_proxy_msg_t) );
	}
	else
	{
		msg->data = NULL;
	}

	// Done creating in msg, lets move in to the proxy
	f_psock_proxy_push_in_msg( msg );

	// Prepare for next read
	alloc_msg_read_request(w_cdev, w_psock);
}

/*
static void psock_complete( struct usb_ep *ep, struct usb_request *req )
{
	struct f_psock * psock = ep->driver_data;
	void *data = req->buf;
	unsigned length = req->length; 
	printk( "psock complete called\n" );
	if ( ep == psock->out_ep )
	{
		printk( "Got a Msg from the host\n" );
		// Get the msg
		// Put msg in the proxy buffer ( if msg not empty )
		// Requeue receive request
	}
	else 
	{
		printk( "Finished sending msg to host" );
		// Free the msg that was sent as we dont need it anymore
		// Get next msg from proxy
		// Queue msg for sending (req->buf, req->length )
		// If no msg for sending try again later
	}

	// Queue buffer back for next data
	usb_ep_queue( ep, req, GFP_ATOMIC );
}
*/

static int alloc_msg_send_request( struct usb_composite_dev *cdev, struct f_psock *psock, struct psock_proxy_msg *msg )
{
	struct usb_request *out_req;
	size_t data_len;
	psock_proxy_msg_packet_t *packet;
	uint32_t packet_len;

	//Calculate the length of the outgoing packet
	data_len = msg->length - sizeof(psock_proxy_msg_t);

	out_req = usb_ep_alloc_request( psock->in_ep, GFP_ATOMIC );
	out_req->buf = kmalloc( data_len+sizeof(psock_proxy_msg_packet_t), GFP_ATOMIC );
	packet = out_req->buf;

	//Copy the message fields to the outgoing packet
	packet_len = psock_proxy_msg_to_packet(msg,packet);

	//Set the out request length to the pacekts size
	out_req->length = packet_len;

	// TODO Check if not to big also
	if ( data_len > 0 )
	{
		/* Copy the data to the remainder of the allocated space */
		memcpy( packet->data, msg->data, data_len );
	}

	// We put a pointer to the msg in the context
	out_req->context = msg;

	out_req->complete = psock_send_complete;
	usb_ep_queue( psock->in_ep, out_req, GFP_ATOMIC );

	return 0;	
}


static int alloc_msg_read_request( struct usb_composite_dev *cdev, struct f_psock *psock )
{
	struct usb_request *out_req;

	printk( "Allocating msg request to read\n" );
	out_req = usb_ep_alloc_request( psock->out_ep, GFP_ATOMIC );
	out_req->length = sizeof( psock_proxy_msg_packet_t ) + PSOCK_GADGET_BUF_SIZE;
	out_req->buf = kmalloc( out_req->length, GFP_ATOMIC );
	out_req->dma = 0;
	out_req->complete = psock_read_complete;
	usb_ep_queue( psock->out_ep, out_req, GFP_ATOMIC );

	return 0;	
}



/**
 * Function allocathes the initial usb requests, for reading and writing.
 */
static int alloc_requests( struct usb_composite_dev *cdev, struct f_psock *psock )
{
	int result = 0;

	struct psock_proxy_msg msg = {0};
	msg.type = F_PSOCK_MSG_NONE;
	msg.length = sizeof(struct psock_proxy_msg );
	
	alloc_msg_send_request( cdev, psock , &msg );
	alloc_msg_read_request( cdev, psock ); 

	return result;

}

/**
 * @todo add error out that disables endpoint when fail
 * @todo check if its better two use 2 functions for the complete part
 */
static int enable_psock( struct usb_composite_dev *cdev, struct f_psock *psock )
{
	int result = 0;
	// Enable the endpoints
	result = enable_endpoint( cdev, psock, psock->in_ep );
	result = enable_endpoint( cdev, psock, psock->out_ep );	
	result = alloc_requests( cdev, psock );

	// @todo check for better way to pass these structs
	w_cdev = cdev;
	w_psock = psock;
	
	queue_delayed_work( f_psock_gadget_work_queue, &f_psock_gadget_work, PSOCK_PROXY_JIFFIES );

	return result;
}

static void disable_psock(struct f_psock *psock )
{
	printk( "f_psock: disable_psock\n" );
	if(psock)
	{
		usb_ep_disable(psock->in_ep);
		usb_ep_disable(psock->out_ep);
	}
}



/**
 * Sets the interface alt setting
 * As we have no alt settings yet value will be zero.
 * But interface should be disabled / enabled again
 */
static int psock_set_alt( struct usb_function *f , unsigned intf, unsigned alt )
{
	int ret;

	struct f_psock	*psock = func_to_psock(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	disable_psock(psock);
	ret = enable_psock(cdev, psock );
	return ret;
}

static void psock_disable(struct usb_function *f )
{
	struct f_psock	*sock = func_to_psock(f);

	disable_psock(sock);	
}


static struct usb_function *psock_alloc(struct usb_function_instance *fi)
{
	struct f_psock_opts *psock_opts;
	struct f_psock *psock;

	printk("Allocating psock function\n" );

	psock = kzalloc( (sizeof *psock ), GFP_KERNEL );
	if ( !psock )
	{
		return ERR_PTR(-ENOMEM);
	}

	psock_opts = container_of(fi, struct f_psock_opts, func_inst );

	mutex_lock(&psock_opts->lock );
	psock_opts->refcnt++;
	mutex_unlock(&psock_opts->lock);

	psock->buflen = psock_opts->bulk_buflen;
	psock->qlen = psock_opts->qlen;

        psock->function.name = "psock";
        psock->function.bind = psock_bind;
        psock->function.set_alt = psock_set_alt;
        psock->function.disable = psock_disable;
        psock->function.strings = psock_strings;

        psock->function.free_func = psock_free_func;

        return &psock->function;

}



/**
 *
 * usb instance allocation handling
 */

static inline struct f_psock_opts *to_f_psock_opts(struct config_item *item)
{
        return container_of(to_config_group(item), struct f_psock_opts,
                            func_inst.group);
}



static ssize_t f_psock_opts_bulk_buflen_show(struct config_item *item, char *page)
{
        struct f_psock_opts *opts = to_f_psock_opts(item);
        int result;

        mutex_lock(&opts->lock);
        result = sprintf(page, "%d\n", opts->bulk_buflen);
        mutex_unlock(&opts->lock);

        return result;
}

static ssize_t f_psock_opts_bulk_buflen_store(struct config_item *item,
                                    const char *page, size_t len)
{
        struct f_psock_opts *opts = to_f_psock_opts(item);
        int ret;
        u32 num;

        mutex_lock(&opts->lock);
        if (opts->refcnt) {
                ret = -EBUSY;
                goto end;
        }

        ret = kstrtou32(page, 0, &num);
        if (ret)
                goto end;

        opts->bulk_buflen = num;
        ret = len;
end:
        mutex_unlock(&opts->lock);
        return ret;
}



CONFIGFS_ATTR(f_psock_opts_, bulk_buflen);

static ssize_t f_psock_opts_qlen_show(struct config_item *item, char *page)
{
        struct f_psock_opts *opts = to_f_psock_opts(item);
        int result;

        mutex_lock(&opts->lock);
        result = sprintf(page, "%d\n", opts->qlen);
        mutex_unlock(&opts->lock);

        return result;
}



static ssize_t f_psock_opts_qlen_store(struct config_item *item,
                                    const char *page, size_t len)
{
        struct f_psock_opts *opts = to_f_psock_opts(item);
        int ret;
        u32 num;

        mutex_lock(&opts->lock);
        if (opts->refcnt) {
                ret = -EBUSY;
                goto end;
        }

        ret = kstrtou32(page, 0, &num);
        if (ret)
                goto end;

        opts->qlen = num;
        ret = len;
end:
        mutex_unlock(&opts->lock);
        return ret;
}



CONFIGFS_ATTR(f_psock_opts_, qlen);

static void psock_attr_release(struct config_item *item)
{
        struct f_psock_opts *psock_opts = to_f_psock_opts(item);

        usb_put_function_instance(&psock_opts->func_inst);
}


static struct configfs_item_operations psock_item_ops = {
        .release                = psock_attr_release,
};


static struct configfs_attribute *psock_attrs[] = {
        &f_psock_opts_attr_qlen,
        &f_psock_opts_attr_bulk_buflen,
        NULL,
};


static struct config_item_type psock_func_type = {
	        .ct_item_ops    = &psock_item_ops,
		.ct_attrs       = psock_attrs,
		.ct_owner       = THIS_MODULE,
};


static void psock_free_instance(struct usb_function_instance *fi)
{
        struct f_psock_opts *psock_opts;

        psock_opts = container_of(fi, struct f_psock_opts, func_inst);
        kfree(psock_opts);
}


static struct usb_function_instance *psock_alloc_inst(void)
{
	struct f_psock_opts *psock_opts;

	psock_opts = kzalloc( sizeof(*psock_opts ) , GFP_KERNEL );
	if ( !psock_opts )
	{
		return ERR_PTR(-ENOMEM);
	}

	mutex_init(&psock_opts->lock);

	psock_opts->func_inst.free_func_inst = psock_free_instance;
	psock_opts->bulk_buflen = PSOCK_GADGET_BUF_SIZE;
	psock_opts->qlen = 1; // At the moment we test with 1 queued transmission

	config_group_init_type_name( &psock_opts->func_inst.group, "", &psock_func_type);

	return &psock_opts->func_inst;
}


DECLARE_USB_FUNCTION(psock, psock_alloc_inst, psock_alloc);

int f_psock_init_gadget( void )
{ 
	printk( "Registering f_psock usb function\n" );
	usb_function_register( &psockusb_func );

	// Work
	f_psock_gadget_work_queue = create_workqueue( "f_psock_gadget_work_queue" );
	INIT_DELAYED_WORK( &f_psock_gadget_work, f_psock_gadget_work_handler );

	return 0;
}


int f_psock_cleanup_gadget( void )
{
	printk( "Unregistering f_psock usb function\n" );
	usb_function_unregister( &psockusb_func);
	return 0;
}


