#include <linux/kernel.h>
#include "psock_proxy_msg.h"

void psock_proxy_msg_to_packet(psock_proxy_msg_t *msg, psock_proxy_msg_packet_t *packet)
{
    packet->magic = cpu_to_be32(msg->magic);
    packet->type = cpu_to_be32(msg->type);
    packet->action = cpu_to_be32(msg->action);
    packet->msg_id = cpu_to_be32(msg->msg_id);
    packet->sock_id = cpu_to_be32(msg->sock_id);
    packet->status = cpu_to_be32(msg->status);
    packet->length = cpu_to_be32(msg->length - sizeof(psock_proxy_msg_t) + sizeof(psock_proxy_msg_packet_t));
    packet->state = cpu_to_be32(msg->state);
}

void psock_proxy_packet_to_msg(psock_proxy_msg_packet_t *packet, psock_proxy_msg_t *msg)
{
    msg->magic = be32_to_cpu(packet->magic);
    msg->type = be32_to_cpu(packet->type);
    msg->action = be32_to_cpu(packet->action);
    msg->msg_id = be32_to_cpu(packet->msg_id);
    msg->sock_id = be32_to_cpu(packet->sock_id);
    msg->status = be32_to_cpu(packet->status);
    msg->length = be32_to_cpu(packet->length) - sizeof(psock_proxy_msg_packet_t) + sizeof(psock_proxy_msg_t);
    msg->state = be32_to_cpu(packet->state);
    msg->data = NULL;
    msg->related = NULL;
    msg->wait_list = (const struct list_head){0};
}
