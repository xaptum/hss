/**
 * @file xarpcd_socket.h
 * @brief Api for the socket part of the xaptum tcp-proxy host part
 */


#ifndef _XARPCD_SOCKET_H__
#define _XAPRCD_SOCKET_H__

#include <linux/net.h>
#include <linux/socket.h>

#include <net/sock.h>


int xarpcd_socket_create( int socket_id );
int xarpcd_socket_connect( int socket_id, struct sockaddr *addr, int addrlen );
int xarpcd_socket_write( int socket_id, void* data, int len );
int xarpcd_socket_read( int socket_id,  void* data,  int len );
int xarpcd_socket_blocking_read( int socket_id, void *data, int maxlen );
int xarpcd_socket_close( int socket_id );



#endif // _XARPCD_SOCKET_H__
