/**
 * @file psock_proxy_msg.h
 * ébrief Definition of the msg structs used for proxying the tcp sockets
 * 	  And some ease of use functions for working with the msgs
 * @author Jeroen Z
 */

#ifndef __PSOCK_PROXY_MSG_H__
#define __PSOCK_PROXY_MSG_H__

#include <linux/types.h>

#define F_PSOCK_SUCCESS 1
#define F_PSOCK_FAIL -1

#define PSOCK_MSG_MAGIC 0xabcd

/**
 * Different types of the msg 
 */
typedef enum psock_msg_type
{
	F_PSOCK_MSG_ACTION_REQUEST, /**< Msg type for requesting an action to the other side */
	F_PSOCK_MSG_ACTION_REPLY,   /**< Msg type for replying as a result of a requested action */
	F_PSOCK_MSG_NONE,	    /**< Empty msg type (can be used to setup communication */
	F_PSOCK_MSG_ASYNC,
} psock_msg_type_t;

/**
 * Possible actions for the proxy
 */
typedef enum psock_proxy_action
{
	F_PSOCK_CREATE,
	F_PSOCK_CONNECT,
	F_PSOCK_READ,
	F_PSOCK_WRITE,
	F_PSOCK_CLOSE,
	F_PSOCK_POLL
} psock_proxy_action_t;

/**
 * The state of the proxy msg withing the proxy
 */
typedef enum psock_proxy_state
{
	MSG_PENDING,
	MSG_SEND,
	MSG_ANSWERED,

} psock_proxy_state_t;

/**
 * The packet to be sent over the network
 */
typedef struct psock_proxy_msg_packet
{
	__le32 magic; 	/**< Should hold the magic number */
	__le32 type;		/**< The msg type */
	__le32 action;		/**< The msg action */
	__le32 msg_id;	/**< Id for the msg, when reply should be the same */
	__le32 sock_id;	/**< Socket id identifier (proxy id ) */
	__le32 status;		/**< Status field used for status of action replies */
	__le32 length; 	/**< total data length of the message including data */
	__le32 state;
	unsigned char data[];
} psock_proxy_msg_packet_t;

typedef struct psock_proxy_msg
{
	uint32_t magic; 	/**< Should hold the magic number */
	uint32_t type;		/**< The msg type */
	uint32_t action;		/**< The msg action */
	uint32_t msg_id;	/**< Id for the msg, when reply should be the same */
	uint32_t sock_id;	/**< Socket id identifier (proxy id ) */
	uint32_t status;		/**< Status field used for status of action replies */
	uint32_t length; 	/**< total data length of the message including data */
	uint32_t state;
	void * data;			/**< Holder necessary to both, but they have no relation between systems */
	struct psock_proxy_msg *related;/**< f_psock only */
	struct list_head wait_list;	/**< f_psock only */
} psock_proxy_msg_t;

void psock_proxy_msg_to_packet(psock_proxy_msg_t *msg, psock_proxy_msg_packet_t *packet);
void psock_proxy_packet_to_msg(psock_proxy_msg_packet_t *packet, psock_proxy_msg_t *msg);

#endif 