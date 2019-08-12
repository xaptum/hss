#include <linux/kernel.h>
#include "xaprc00x-proxy_msg.h"

void psock_proxy_msg_to_packet(psock_proxy_msg_t *msg, psock_proxy_msg_packet_t *packet)
{
    packet->magic = cpu_to_le32(msg->magic);
    packet->type = cpu_to_le32(msg->type);
    packet->action = cpu_to_le32(msg->action);
    packet->msg_id = cpu_to_le32(msg->msg_id);
    packet->sock_id = cpu_to_le32(msg->sock_id);
    packet->status = cpu_to_le32(msg->status);
    packet->length = cpu_to_le32(msg->length - sizeof(psock_proxy_msg_t) + sizeof(psock_proxy_msg_packet_t));
    packet->state = cpu_to_le32(msg->state);
}

void psock_proxy_packet_to_msg(psock_proxy_msg_packet_t *packet, psock_proxy_msg_t *msg)
{
    msg->magic = le32_to_cpu(packet->magic);
    msg->type = le32_to_cpu(packet->type);
    msg->action = le32_to_cpu(packet->action);
    msg->msg_id = le32_to_cpu(packet->msg_id);
    msg->sock_id = le32_to_cpu(packet->sock_id);
    msg->status = le32_to_cpu(packet->status);
    msg->length = le32_to_cpu(packet->length) - sizeof(psock_proxy_msg_packet_t) + sizeof(psock_proxy_msg_t);
    msg->state = le32_to_cpu(packet->state);
    msg->data = NULL;
    msg->related = NULL;
    msg->wait_list = (const struct list_head){0};
}