// SPDX-License-Identifier: GPL-2.0+
/**
 * hss.c -- A socket driver for Xaptums HSS implementation
 *
 * Copyright (C) 2018-2019 Xaptum, Inc.
 */
#include <linux/module.h>
#include <linux/net.h>
#include <linux/hss.h>
#include <linux/rhashtable.h>
#include <linux/sched/signal.h>
#include <net/sock.h>
#include <net/hss.h>
#include "hss.h"

#define HSS_SK_BUFF_SIZE 512
#define HSS_SK_SND_TIMEO (HZ * 30)

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("HSS Socket Driver");
MODULE_VERSION("0.0.1");

/**
 * In addition to the Linux sock information we need to keep track of the local
 * ID given to us by the proxy
 */
enum hss_state {
	HSS_UNOPEN = 0, /* Initial state, unopened */
	HSS_ESTABLISHED, /* Connection established */
	HSS_SYN_SENT, /* Sent a connection request, waiting for ACK */
	/* A connection request has been responded to but not processed */
	HSS_SYN_RECV,
	HSS_CLOSING, /* Our side has closed, waiting for host */
	HSS_CLOSE_WAIT, /* Remote has shut down and is waiting for us */
	HSS_CLOSE, /* Close has been completed or open is in flight */

	HSS_STATE_MAX
};

struct hss_pinfo {
	struct sock		sk;
	int			local_id;
	atomic_t		state; /* enum hss_state */
	__u8			so_error;
	char			*read_cache;
	size_t			read_cache_offset;
	size_t			read_cache_bytes_used;
	size_t			read_cache_size;
	struct hss_packet *wait_ack;
	struct rhash_head hash;
};

static struct rhashtable_params ht_parms = {
	.nelem_hint = 8,
	.key_len = sizeof(int),
	.key_offset = offsetof(struct hss_pinfo, local_id),
	.head_offset = offsetof(struct hss_pinfo, hash),
};

/* Forward Declarations */
struct sock *hss_get_sock(int key);

/* This socket driver may only be linked to one HSS proxy instance */
static void *g_proxy_context;
struct rhashtable g_hss_socket_table;
static atomic_t g_sock_id;

/**
 * Closes the socket on the device side.
 */
static void hss_sock_side_shutdown_internal(struct sock *sk, int how)
{
	struct hss_pinfo *psk = (struct hss_pinfo *)sk;

	lock_sock(sk);
	sk->sk_shutdown |= how;

	/**
	 * Note: This is mostly legacy since sendmsg and recvmsg only use
	 * sk_shutdown flags. Removal of psk->state is likely in future
	 * releases.
	 */
	atomic_set(&psk->state, HSS_CLOSE);
	sk->sk_state_change(sk);
	release_sock(sk);
}

/**
 * When the device initiates a shutdown it performs the internal tasks and
 * sends a command to the host.
 */
static int hss_sock_side_shutdown(struct socket *socket, int how)
{
	struct sock *sk = socket->sk;
	struct hss_pinfo *psk = (struct hss_pinfo *)sk;
	int local_id;

	/**
	 * maps 0->1 has the advantage of making bit 1 rcvs and
	 * 1->2 bit 2 snds.
	 * 2->3
	 */
	how++;
	if ((how & ~SHUTDOWN_MASK) || !how) /* MAXINT->0 */
		return -EINVAL;

	hss_sock_side_shutdown_internal(sk, how);

	/* Send shutdown to peer */
	hss_proxy_close_socket(psk->local_id, g_proxy_context);
	return 0;
}

/**
 * For the proxy to run when a shutdown is received from the host.
 */
int hss_sock_handle_host_side_shutdown(int sock_id, int how)
{
	struct sock *sk;

	/**
	 * maps 0->1 has the advantage of making bit 1 rcvs and
	 * 1->2 bit 2 snds.
	 * 2->3
	 */
	how++;
	if ((how & ~SHUTDOWN_MASK) || !how) /* MAXINT->0 */
		return -EINVAL;

	sk = hss_get_sock(sock_id);
	if (sk)
		hss_sock_side_shutdown_internal(sk, how);

	return 0;
}

static int hss_sock_side_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		struct hss_pinfo *psk = (struct hss_pinfo *)sk;

		lock_sock(sk);

		rhashtable_remove_fast(&g_hss_socket_table, &psk->hash,
				       ht_parms);
		sock->sk = NULL;
		sk->sk_shutdown = SHUTDOWN_MASK;
		sk->sk_state_change(sk);
		sock_orphan(sk);

		release_sock(sk);

		sock_put(sk);
	} else {
		pr_err("%s: Given sock->sk==NULL. Hash table corruption "
			"possible.", __func__);
	}

	return 0;
}

/**
 * Function for connecting a socket
 */
static void hss_def_write_space(struct sock *sk)
{
	struct socket_wq *wq;
	struct hss_pinfo *psk = (struct hss_pinfo *)sk;

	wq = rcu_dereference(sk->sk_wq);
	wake_up_interruptible_all(&wq->wait);
	sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
}

static void hss_def_readable(struct sock *sk)
{
	struct socket_wq *wq;
	struct hss_pinfo *psk = (struct hss_pinfo *)sk;

	wq = rcu_dereference(sk->sk_wq);
	wake_up_interruptible_sync_poll(&wq->wait, POLLIN | POLLPRI |
		POLLRDNORM | POLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
}

/**
 * Funciton for handling a CONNECT ack
 */
void hss_sock_connect_ack(int sock_id, struct hss_packet *packet)
{
	struct socket_wq *wq;
	struct hss_pinfo *psk;
	struct sock *sk;

	sk = hss_get_sock(sock_id);
	psk = (struct hss_pinfo *)sk;

	/* This usually means the sock was shut down while in transit. */
	if (!psk) {
		pr_err("%s: Socket %d not found",
			__func__, sock_id);
		return;
	}
	
	wq = rcu_dereference(sk->sk_wq);

	/* Let the sock know we got a response */
	psk->wait_ack = packet;
	atomic_set(&psk->state, HSS_SYN_RECV);
	wake_up_interruptible_all(&wq->wait);
}

static long hss_wait_for_connect(struct sock *sk, long timeo)
{
	struct hss_pinfo *psk;

	psk = (struct hss_pinfo *)sk;

	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(sk_sleep(sk), &wait);

	while (atomic_read(&psk->state) == HSS_SYN_SENT) {
		release_sock(sk);
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
		lock_sock(sk);

		if (signal_pending(current) || !timeo)
			break;
	}

	remove_wait_queue(sk_sleep(sk), &wait);
	return timeo;
}

/**
 * hss_realloc_shift - Reallocs a buffer but only copies part of the data
 *
 * @p A pointer to the location of the memory to be reallocated
 * @new_size The minimum size for the new buffer
 * @flags Flags to pass to kmalloc
 * @copy_start The offset to apply when copying the old data
 * @copy_len The number of bytes to copy to the new buffer
 *
 * This function uses kmalloc and free to act like krealloc, except instead of
 * copying the entire buffer over to the new memory, only a single continuous
 * segment of data is taken. This data can start anywhere in the buffer and can
 * be any length.
 *
 * Returns: The new length of the buffer
 *
 * @notes
 * This function may generate a segment violation if copy_start+copy_len
 * exceeds the length of the original buffer.
 *
 * This function will cause undefined behavior if *p is not a block of memory
 * defined by the kmalloc family of functions.
 *
 * This function will round new_size up to the nearest power of 2 when
 * selecting a new buffer size.
 */
static size_t hss_realloc_shift(void **p, size_t new_size, gfp_t flags,
	size_t copy_start, size_t copy_len)
{
	char *new_mem = kmalloc(new_size, flags);

	new_size = round_up(new_size, 2);

	if (p) {
		memcpy(new_mem, ((char *)*p) + copy_start, copy_len);
		kfree(*p);
	}

	*p = new_mem;
	return new_size;
}

void hss_sock_transmit(int sock_id, void *data, int len)
{
	struct hss_pinfo *psk;
	struct sock *sk;
	int free_space;
	int noshift_len;
	int write_offset;

	psk = (struct hss_pinfo *)hss_get_sock(sock_id);

	/* This usually means the sock was shut down while in transit. */
	if (!psk) {
		pr_err("%s: Socket %d not found\n", __func__, sock_id);
		return;
	}

	sk = &psk->sk;

	lock_sock(sk);

	/* How much space is currently in the buffer? */
	free_space = psk->read_cache_size - psk->read_cache_bytes_used;

	/* The length required to append the incoming data without shifting */
	noshift_len =
		psk->read_cache_offset + psk->read_cache_bytes_used + len;

	/* If there is not enough space in the buffer, reallocate */
	if (free_space < len) {
		psk->read_cache_size =
			hss_realloc_shift(
				(void **)&psk->read_cache,
				psk->read_cache_size + len,
				GFP_KERNEL,
				psk->read_cache_offset,
				psk->read_cache_bytes_used);
		psk->read_cache_offset = 0;
	} else if (noshift_len > psk->read_cache_size) {
		/**
		 * If there is sufficient room but it isn't continuous then
		 * move existing to the top.
		 */
		memcpy(psk->read_cache,
			psk->read_cache + psk->read_cache_offset,
			psk->read_cache_bytes_used);
		psk->read_cache_offset = 0;
	}

	/* Append the incoming data immediately after the existing data */
	write_offset = psk->read_cache_offset + psk->read_cache_bytes_used;
	memcpy(psk->read_cache + write_offset, data, len);
	psk->read_cache_bytes_used += len;

	release_sock(sk);
	sk->sk_data_ready(sk);
}

/**
 * Funciton for sending a CONNECT
 */
static int hss_sock_connect(struct socket *sock, struct sockaddr *addr,
	int alen, int flags)
{
	struct hss_pinfo *psk;
	struct sock *sk;
	int state;
	int ret = -1;

	sk = sock->sk;
	psk = (struct hss_pinfo *)sk;

	lock_sock(sk);

	state = atomic_read(&psk->state);

	if (state == HSS_SYN_SENT) {
		ret = -EALREADY;
	} else if (state == HSS_ESTABLISHED) {
		ret = -EISCONN;
	} else {
		int new_status;
		long timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

		atomic_set(&psk->state, HSS_SYN_SENT);
		hss_proxy_connect_socket(psk->local_id, addr, alen,
			g_proxy_context);

		/* Exit immediately if asked not to block */
		if (!timeo || !hss_wait_for_connect(sk, timeo)) {
			ret = -EINPROGRESS;
			goto out;
		}

		/* If interrupted the error is either -ERESTARTSYS or -EINTR */
		ret = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;

		if (psk->wait_ack->ack.code == HSS_E_SUCCESS) {
			new_status = HSS_ESTABLISHED;

			/* Let poll know that we can write now */
			sk->sk_write_space = hss_def_write_space;
			sk->sk_data_ready = hss_def_readable;
			sk->sk_write_space(&psk->sk);
			ret = 0;
		} else {
			struct socket_wq *wq = rcu_dereference(sk->sk_wq);

			new_status = HSS_CLOSE;

			wake_up_interruptible_all(&wq->wait);
			sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
			ret = -1;
		}
		atomic_set(&psk->state, new_status);
	}

out:
	release_sock(sk);
	return ret;
}

/**
 * Function for sending a msg over the socket
 */
static int hss_sock_sendmsg(struct socket *sock,
				 struct msghdr *msg, size_t len)
{
	void *data;
	int bytes_copied;
	int bytes_sent;
	struct hss_pinfo *psk;
	struct sock *sk;

	sk = sock->sk;
	psk = (struct hss_pinfo *)sk;

	/* If the sock has already been freed */
	if (!sk) {
		bytes_sent = -EPIPE;
		goto out_nolock;
	}

	lock_sock(sk);

	/* If outgoing transmissions have been shut down */
	if (sk->sk_shutdown & SEND_SHUTDOWN) {
		bytes_sent = -EPIPE;
		goto out_release;
	}

	/* If not connected */
	if (atomic_read(&psk->state) != HSS_ESTABLISHED) {
		bytes_sent = -ENOTCONN;
		goto out_release;
	}

	/* Copy the data over */
	data = kmalloc(len, GFP_KERNEL);
	bytes_copied = copy_from_iter(data, len, &msg->msg_iter);

	/* This operation can be lengthy and we don't need the lock */
	release_sock(sk);
	bytes_sent = hss_proxy_write_socket(psk->local_id, data,
		bytes_copied, g_proxy_context);
	goto out_nolock;

out_release:
	release_sock(sk);
out_nolock:
	return bytes_sent;
}

static int hss_sock_wait_for_data(struct socket *sock,
	int min_bytes, int timeo)
{
	struct hss_pinfo *psk;
	struct sock *sk;

	sk = sock->sk;
	psk = (struct hss_pinfo *)sk;

	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(sk_sleep(sk), &wait);

	while (psk->read_cache_bytes_used < min_bytes) {
		release_sock(sk);
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
		lock_sock(sk);

		if (signal_pending(current) || !timeo)
			break;
	}

	remove_wait_queue(sk_sleep(sk), &wait);
	return timeo;
}

/**
 * Function for recv msg from the socket
 */
static int hss_sock_recvmsg(struct socket *sock,
				struct msghdr *msg, size_t size, int flags)
{
	struct hss_pinfo *psk;
	int target;
	long timeo;
	struct sock *sk;
	int ret = 0;

	sk = sock->sk;
	psk = (struct hss_pinfo *)sk;

	lock_sock(sock->sk);

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Handle not having enough bytes to return immediately */
	target = (flags & MSG_WAITALL) ? size : 1;
	if (target > psk->read_cache_bytes_used &&
		!(sk->sk_shutdown & RCV_SHUTDOWN)) {
		/* Exit if we can't block or timed out before data came in */
		if (!timeo && !hss_wait_for_connect(sk, timeo)) {
			ret = -EWOULDBLOCK;
			goto out;
		}

		hss_sock_wait_for_data(sock, target, timeo);

		/* If interrupted the error is either -ERESTARTSYS or -EINTR */
		if (signal_pending(current)) {
			ret = sock_intr_errno(timeo);
			goto out;
		}
	}

	if (psk->read_cache_bytes_used > 0) {
		/* Never return more bytes than requested */
		ret = (psk->read_cache_bytes_used > size) ?
			size : psk->read_cache_bytes_used;
		copy_to_iter(psk->read_cache + psk->read_cache_offset,
			ret, &msg->msg_iter);
		psk->read_cache_bytes_used -= ret;
		psk->read_cache_offset += ret;
	}

out:
	release_sock(sock->sk);
	return ret;
}

static unsigned int hss_sock_poll(struct file *file, struct socket *socket,
	poll_table *wait)
{
	struct hss_pinfo *psk;
	struct sock *sk;
	unsigned int mask;
	int state;

	sk = socket->sk;
	psk = (struct hss_pinfo *)sk;
	mask = 0;

	sock_poll_wait(file, socket, wait);

	state = atomic_read(&psk->state);

	/* POLLHUP if and only if both sides are shut down. */
	if (sk->sk_shutdown == SHUTDOWN_MASK && state == HSS_CLOSE) {
		mask |= POLLHUP;
		return mask;
	}
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	/* Decide readability */
	if (psk->read_cache_bytes_used > 0)
		mask |= POLLIN | POLLRDNORM;

	/* Connected sockets are always writable */
	if (state == HSS_ESTABLISHED)
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

	return mask;
}

/**
 * Operation definitions for the psock type
 */
static const struct proto_ops hss_ops = {
	.family		= PF_HSS,
	.owner		= THIS_MODULE,
	.release	= hss_sock_side_release,
	.shutdown	= hss_sock_side_shutdown,
	.bind		= sock_no_bind,
	.connect	= hss_sock_connect,
	.listen		= sock_no_listen,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.sendmsg	= hss_sock_sendmsg,
	.recvmsg	= hss_sock_recvmsg,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.ioctl		= sock_no_ioctl,
	.poll		= hss_sock_poll,
	.socketpair	= sock_no_socketpair,
	.mmap		= sock_no_mmap
};

/**
 * PSOCK proto definition
 */
static struct proto hss_proto = {
	.name = "HSS",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct hss_pinfo)
};

/**
 * Allocate socket data
 */
static struct sock *hss_sock_alloc(struct net *net, struct socket *sock,
	int proto, gfp_t prio, int kern)
{
	struct sock *sk;

	sk = sk_alloc(net, PF_HSS, prio, &hss_proto, kern);
	if (!sk)
		goto exit;

	sock_init_data(sock, sk);

	sk->sk_destruct = NULL;
	sk->sk_sndtimeo = HSS_SK_SND_TIMEO;
	sk->sk_sndbuf = HSS_SK_BUFF_SIZE;
	sk->sk_rcvbuf = HSS_SK_BUFF_SIZE;

	refcount_set(&sk->sk_refcnt, 1);

	sock_reset_flag(sk, SOCK_ZAPPED);

	sk->sk_protocol = proto;
exit:
	return sk;
}

static long hss_wait_for_create(struct sock *sk, long timeo)
{
	struct hss_pinfo *psk;

	psk = (struct hss_pinfo *)sk;

	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(sk_sleep(sk), &wait);

	while (atomic_read(&psk->state) != HSS_UNOPEN) {
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);

		/* If we were interrupted or hit the timeout */
		if (signal_pending(current) || !timeo)
			break;
	}

	remove_wait_queue(sk_sleep(sk), &wait);
	return timeo;
}

/**
 * Create a socket for the psock type
 */
static int hss_sock_create(struct net *net, struct socket *sock, int protocol,
	int kern)
{
	struct sock *sk;
	struct hss_pinfo *psk;
	int ret;
	long timeo;

	sock->state = SS_UNCONNECTED;
	sock->ops = &hss_ops;

	sk = hss_sock_alloc(net, sock, protocol, GFP_ATOMIC, kern);
	if (!sk) {
		pr_err("hss_proxy: ENOMEM when creating socket\n");
		ret = -ENOMEM;
		goto out;
	}

	psk =  (struct hss_pinfo *)sk;
	atomic_set(&psk->state, HSS_UNOPEN);

	/* Create the socks entry in our table */
	psk->local_id = atomic_inc_return(&g_sock_id);
	rhashtable_lookup_insert_fast(&g_hss_socket_table,
		&psk->hash, ht_parms);
	atomic_set(&psk->state, HSS_CLOSE);

	/* Send the OPEN command to the proxy */
	hss_proxy_open_socket(psk->local_id, g_proxy_context);

	/* Block until we get an ACK */
	/* Blocking it assumed to be allowed for the time being */
	timeo = sk->sk_sndtimeo;

	/* Exit immediately if the block timed out */
	if (!hss_wait_for_create(sk, timeo)) {
		ret = -EINPROGRESS;
		goto out;
	}

	/* If interrupted the error is either -ERESTARTSYS or -EINTR */
	if (signal_pending(current)) {
		ret = sock_intr_errno(timeo);
		goto out;
	}

	/* Handle the ack and reinsert on success */
	ret = psk->wait_ack->ack.code;
	if (ret) {
		pr_err("hss_proxy: Host failed OPEN with code %d", ret);
		rhashtable_remove_fast(&g_hss_socket_table, &psk->hash,
			ht_parms);
	}

	/* The proxy expects us to free the buffer */
	kfree(psk->wait_ack);
	psk->wait_ack = NULL;

out:
	return ret;
}

/**
 * Proto family definition
 */
static const struct net_proto_family hss_family_ops = {
	.family		= PF_HSS,
	.owner		= THIS_MODULE,
	.create		= hss_sock_create
};

void hss_sock_open_ack(int sock_id, struct hss_packet *ack)
{
	struct hss_pinfo *psk;
	struct sock *sk;
	struct socket_wq *wq;

	sk = hss_get_sock(sock_id);
	psk = (struct hss_pinfo *)sk;

	/* These should never happen */
	if (!psk) {
		pr_err("%s: Sock %d not found\n",
			__func__, sock_id);
		return;
	}
	if (psk->wait_ack) {
		pr_err("%s: Sock %d busy\n",
			__func__, sock_id);
		return;
	}

	psk->wait_ack = ack;
	atomic_set(&psk->state, HSS_UNOPEN);

	wq = rcu_dereference(sk->sk_wq);
	wake_up_interruptible_all(&wq->wait);
}

/**
 * hss_register - Initializes the socket type and registers the calling
 * proxy instance.
 *
 * @proxy_context A pointer to the HSS proxy instance
 *
 * Initializes HSS socket protocol and remembers a pointer to the proxys
 * inst to send back whenever our driver calls the proxy.
 *
 * Returns: A pointer to the instance for this proxy.
 *
 * @notes
 * When the HSS socket is initialized it must have an instance of the proxy to
 * pass back when it makes calls. This driver can only use one instance of the
 * HSS proxy but the HSS proxy may have many instances.
 *
 * This function will be called by the HSS proxy when it is ready to transmit
 * data between this module and the USB device.
 */
int hss_register(void *proxy_context)
{
	int err;

	if (g_proxy_context) {
		err = -EEXIST;
		goto exit;
	}
	g_proxy_context = proxy_context;

	err = proto_register(&hss_proto, 0);
	if (err < 0) {
		pr_debug("Error registering psock protocol");
		goto clear_context;
	}

	err = sock_register(&hss_family_ops);
	if (err < 0) {
		pr_debug("Error registering socket");
		goto clear_context;
	}

	return 0;
clear_context:
	g_proxy_context = NULL;
exit:
	return err;
}

struct sock *hss_get_sock(int key)
{
	return rhashtable_lookup_fast(&g_hss_socket_table, &key, ht_parms);
}

/**
 * Cleanup and unregister registred types
 */
static void __exit hss_cleanup_sockets(void)
{
	proto_unregister(&hss_proto);
	sock_unregister(hss_family_ops.family);
	rhashtable_destroy(&g_hss_socket_table);
}

static int __init hss_init_sockets(void)
{
	rhashtable_init(&g_hss_socket_table, &ht_parms);
	return 0;
}

subsys_initcall(hss_init_sockets);
module_exit(hss_cleanup_sockets);
