/**
 * @file f_psock_proxy.h
 * @brief The proxy part of the psock driver, handles the buffering and proxying of the socket requests.
 * Two main parts of the api, are the socket side and the usb side
 * The socket side, will translate the USB msgs to socket reqeust and vice versa.
 * The usb side will allow the pushing / popping of msgs from the buffer.
 */

#ifndef _F_PSOCK_PROXY_H_
#define _F_PSOCK_PROXY_H_

#include <linux/types.h>
#include <linux/net.h>
#include <net/sock.h>

/**
 * Struct for holding proxy socket information
 */
typedef struct f_psock_proxy_socket
{
        int local_id; // The local socket id for the socket
} f_psock_proxy_socket_t;

/******************************************************************************************
 * Init and cleanup
 ******************************************************************************************/

int f_psock_proxy_init( void );
int f_psock_proxy_cleanup( void );

/*******************************************************************************************
 * API functions towards the socket side of the driver
 *******************************************************************************************/

/**
 * Create a socket, the struct will be filled out
 */
int f_psock_proxy_create_socket( f_psock_proxy_socket_t *psk );

/**
 * Delete a socket
 */
int f_psock_proxy_delete_socket( f_psock_proxy_socket_t *psk );

/**
 * Connect socket to address
 */
int f_psock_proxy_connect_socket( f_psock_proxy_socket_t *psk, struct sockaddr *addr, int alen );

/**
 * Write data to the socket
 */
int f_psock_proxy_write_socket( f_psock_proxy_socket_t *psk, void *data, size_t len );

/**
 * Read from the socket
 */
int f_psock_proxy_read_socket( f_psock_proxy_socket_t *psk, void *data, size_t size );

/************************************************************************************
 * API Fucntions towards the usb composite part of the driver
 * Functions will handle the pushing / popping of msgs from the msg buffer
 ************************************************************************************/

/**
 * usb side can use this function to pop the next msg from the queue of msgs
 */
int f_psock_proxy_pop_out_msg( void ** msg );

/**
 * usb side can use this function to push an incomming msg on the in queue
 */
int f_psock_proxy_push_in_msg( void *msg );

#endif
