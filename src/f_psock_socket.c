/**
 * @file f_psock_socket.c
 * @brief Create the psock socket type
 *  This creates a new socket type for proxying to the connected host device
 *  This part of the module communicates with the psock_proxy part
 * @author Jeroen Z
 */

#include "f_psock_proxy.h"

#include <linux/net.h>
#include <net/sock.h>

#define PF_XPT PF_NFC

#define PSOCK_SK_BUFF_SIZE 512
#define PSOCK_SK_SND_TIMEO 1000

/**
 * psock local socket data
 */
struct f_psock_pinfo
{
	struct sock		sk; 	 /**< @note Needs to be here as first entry !! */
	struct f_psock_proxy_socket psk; /**< our local socket information */
};

/**
 * kill the socket
 * Sets flag for removal
 */
static void f_psock_sock_kill(struct sock *sk )
{
	sock_set_flag(sk, SOCK_DEAD);
	sock_put(sk);
}

/**
 * Function called for socket shutdown
 */
static int f_psock_sock_shutdown(struct socket *sock, int how )
{
	struct sock *sk = sock->sk;
        struct f_psock_pinfo *psk = (struct f_psock_pinfo *)sk;

	printk( KERN_INFO "f_psock_socket : socket shutdown :%d\n", psk->psk.local_id );

        f_psock_proxy_delete_socket( &psk->psk );
	
	if (!sk)
	{
		return 0;
	}

	if (!sk->sk_shutdown) 
	{
		sk->sk_shutdown = SHUTDOWN_MASK;
	}


	release_sock(sk);

	return 0;	
}


/**
 * Function called when releasing a socket
 */
static int f_psock_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	int err;
	printk( KERN_INFO "f_psock_socket : releasing socket\n" );

	if ( !sk ) 
	{
		return 0;
	}

	err = f_psock_sock_shutdown(sock, 2 );

	sock_orphan(sk);

	f_psock_sock_kill(sk);

	return err;
}

/**
 * Function for connecting a socket
 */
static int f_psock_sock_connect(struct socket *sock, struct sockaddr *addr, int alen, int flags )
{	
	int res = -1;
	struct f_psock_pinfo *psk = (struct f_psock_pinfo *)sock->sk;

	printk( KERN_INFO "psock_socket : Connecting socket : %d\n", psk->psk.local_id );

	res = f_psock_proxy_connect_socket( &psk->psk, addr, alen );

	return res;
}

/**
 * Function for getname
 */
/*
static int f_psock_sock_getname(struct socket *sock, struct sockaddr *addr, int peer )
{
	printk( KERN_INFO "psock getname\n" );
	return 0;
}
*/

/**
 * Function for sending a msg over the socket
 */
static int f_psock_sock_sendmsg( struct socket *sock,
				 struct msghdr *msg, size_t len )
{
	int res, r;
	void *data = kmalloc( len, GFP_KERNEL );
	struct f_psock_pinfo *psk = (struct f_psock_pinfo *)sock->sk;

	printk( KERN_INFO "psock_socket: sendmsg :%d %ld\n", psk->psk.local_id, len );
	r = copy_from_iter( data, len,  &msg->msg_iter);
	if ( r < len )
	{
		printk( KERN_INFO "psock_socket: sendmsg itercpy incomplete\n" );
	}

	res = f_psock_proxy_write_socket( &psk->psk, data , len );

	return res;
}

/**
 * Function for recv msg from the socket
 */
static int f_psock_sock_recvmsg(struct socket *sock,
				struct msghdr *msg, size_t size, int flags )
{
	int res, r;
	struct f_psock_pinfo *psk = (struct f_psock_pinfo *)sock->sk;
	char *buf = kmalloc( size, GFP_KERNEL );

	printk( KERN_INFO "psock_socket: recvmsg %d\n", psk->psk.local_id );

	res = f_psock_proxy_read_socket( &psk->psk, buf, size );
	
	r = copy_to_iter( buf, res, &msg->msg_iter );	
	if ( r < res )
	{
		printk( KERN_INFO "psock_socket: iter copy incomplete\n" );
	}

	kfree( buf );

	return res;
}


/**
 * Bind an address to the socket
 */
static int f_psock_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	printk( KERN_INFO "f_psock_socket : bind not supported on psock socket\n" );
	return 0;
}

/**
 * Operation definitions for the psock type
 */
static const struct proto_ops f_psock_ops =
{
	.family		= PF_XPT,
	.owner		= THIS_MODULE,
	.release	= f_psock_sock_release,
	.bind		= f_psock_sock_bind,
	.connect	= f_psock_sock_connect,
	.listen		= NULL,
	.accept		= NULL,
	.getname 	= NULL, // f_psock_sock_getname,
	.sendmsg	= f_psock_sock_sendmsg,
	.recvmsg	= f_psock_sock_recvmsg,
	.shutdown	= f_psock_sock_shutdown,
	.setsockopt	= NULL,
	.getsockopt	= NULL,
	.ioctl		= NULL,
	.poll		= NULL,
	.socketpair 	= sock_no_socketpair,
	.mmap		= sock_no_mmap

};

/**
 * PSOCK proto definition
 */
static struct proto f_psock_proto =
{
	.name = "PSOCK",
	.owner = THIS_MODULE,
	.obj_size = sizeof( struct f_psock_pinfo )
};

/**
 * Socket destruction
 */
static void f_psock_sock_destruct(struct sock *sk)
{
//	skb_queue_purge(&sk->sk_receive_queue);
//	skb_queue_purge(&sk->sk_write_queue);
}

/**
 * Allocate socket data
 */
static struct sock *f_psock_sock_alloc(struct net *net, struct socket *sock, int proto, gfp_t prio, int kern)
{
	struct sock *sk;

	printk( KERN_INFO "psock_socket: Allocating sk socket\n" );
	sk = sk_alloc(net, PF_XPT, prio, &f_psock_proto , kern);

	if ( !sk )
	{
		printk( KERN_ERR "psock_socket: Error allocating sk socket\n" );
		return NULL;
	}
	
	sock_init_data(sock, sk);

	sk->sk_destruct = f_psock_sock_destruct;
	sk->sk_sndtimeo = PSOCK_SK_SND_TIMEO;
	sk->sk_sndbuf = PSOCK_SK_BUFF_SIZE;
	sk->sk_rcvbuf = PSOCK_SK_BUFF_SIZE;

	sock_reset_flag(sk, SOCK_ZAPPED);

	sk->sk_protocol = proto;
//	sk->sk_state = BT_OPEN;

	return sk;
}

/**
 * Initialize the local socket data in the socket
 * And let the proxy know we are creating a new socket
 */
static void f_psock_sock_init(struct sock *sk, struct sock *parent)
{
	
	struct f_psock_pinfo *psk = (struct f_psock_pinfo *)sk;
	f_psock_proxy_create_socket( &psk->psk );	
}

/**
 *  Create a socket for the psock type 
 */
static int f_psock_sock_create( struct net *net, struct socket *sock, int protocol, int kern)
{

	struct sock *sk;

	printk( KERN_INFO "psock_proxy: Creating socket\n" );
	
	sock->state = SS_UNCONNECTED;
	sock->ops = &f_psock_ops;

	sk = f_psock_sock_alloc(net, sock, protocol, GFP_ATOMIC, kern);
	if ( !sk )
	{
		printk( KERN_ERR "psock_proxy: ENOMEM when creating socket\n" );
		return -ENOMEM;
	}

	f_psock_sock_init(sk, NULL);

	return 0;
}

/**
 * Proto family definition
 */
static const struct net_proto_family f_psock_family_ops = 
{
	.family		= PF_XPT,
	.owner		= THIS_MODULE,
	.create		= f_psock_sock_create
};

/**
 * psock socket initialization, will register the protocol and socket types with the kernel
 * So the kernel can create sockets of this type when asked for
 */
int f_psock_init_sockets(void )
{
	int err;
	err = proto_register(&f_psock_proto, 0);
	if ( err < 0 )
	{
		printk( KERN_INFO "Error registering psock protocol\n" );
		return err;
	}

	err = sock_register( &f_psock_family_ops );
	if ( err < 0 )
	{
		printk( KERN_INFO "Error registering socket\n" );
		return err;
	}

	return err;
}

/**
 * Cleanup and unregister registred types 
 */
int f_psock_cleanup_sockets(void)
{
	proto_unregister( &f_psock_proto );
	sock_unregister( f_psock_family_ops.family );
	return 0;
}


