/**
 * @file xaprcd_proxy.h
 * @brief Api for the proxy part of the host driver for teh tcp-proxy project
 */

#ifndef _XARPCD_PROXY_H_
#define _XARPCD_PROXY_H_

int xarpcd_proxy_init( void );
int xarpcd_proxy_cleanup( void );

int xarpcd_proxy_pop_in_msg( void **msg );
int xarpcd_proxy_pop_out_msg( void **msg );
int xarpcd_proxy_push_in_msg( void *msg );
int xarpcd_proxy_push_out_msg( void *msg );
void xarpcd_proxy_shutdown_now( void );

#endif // _XARPCD_PROXY_H_
