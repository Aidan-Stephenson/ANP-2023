/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include "subuff.h"
#include "tcp.h"

#include "systems_headers.h"
#include "ethernet.h"
#include "utilities.h"
#include "ip.h"
#include "anp_netdev.h"
#include "route.h"


// Function to return tcp_session from tcp_session_list
struct tcp_session *get_tcp_session(uint16_t dst_port) {
    struct list_head *item;
    struct tcp_session *tcp_ses = TCP_SESSIONS;
    while (tcp_ses != NULL) {
        if (tcp_ses->dst_port == dst_port) {
            return tcp_ses;
        }
        tcp_ses = tcp_ses->next;
    }
    
    return NULL;

}


struct tcp_hdr* init_tcp_packet() {
    struct tcp_hdr *packet = (struct tcp_hdr *)calloc(sizeof(struct tcp_hdr), 1);
    // TODO: Randomize
    packet->seq_num = htonl(0);
    packet->ack_num = htonl(0);

    // TODO: allocate port
    // packet->src_port = htons(src_port);

    
    packet->window_size = htons(1600); // Honestly don't know
    packet->urgent_ptr = htons(0); // We don't use it

    return packet;
}


void tcp_rx(struct subuff *sub){
    struct tcp_hdr *tcp_hdr = tcp_header(sub);

    debug_TCP("Received tcp_rx packet:", tcp_hdr);

    if (tcp_hdr->flags & FIN) {
        // TODO: FIN flag
        printf("FIN flag is set\n");
    }
    if (tcp_hdr->flags & SYN && !(tcp_hdr->flags & ACK)) {
        // struct tcp_hdr syn_ack_packet;
        // //syn_ack_packet.src_port = htons(src_port); // TODO: allocate port
        // syn_ack_packet.dst_port = htons(tcp_hdr->src_port); //TODO: FIND PORT
        // syn_ack_packet.seq_num = htonl(0);  //TODO: server's initial sequence number should be randomly generated
        // syn_ack_packet.ack_num = htonl(ntohl(tcp_hdr->seq_num) + 1);  //CAUTION!! conversion might be wrong //it should be seq_num from syn packet + 1
        // syn_ack_packet.flags = SYNACK; //SYNACK flag is defined as SYN+ACK
        // syn_ack_packet.window_size = htons(1600);
        // syn_ack_packet.urgent_ptr = htons(0); // We don't use it

        // struct tcp_ses *tcp_session = get_tcp_session(tcp_hdr->src_port);
        // if (tcp_session == NULL) {
        //     // TODO: Create session
        //     printf("Cannot find tcp session for SYN\n");
        //     return;
        // }
        // // Set the tcp session state to TCP_SYN_RCVD
        // tcp_session->state = TCP_SYN_RECEIVED;
        // // TODO: send ACK

        printf("SYN flag is set\n");
    }
    if (tcp_hdr->flags & SYN && tcp_hdr->flags & ACK) {
        printf("SYNACK flag is set\n");
        
        struct tcp_session *tcp_session = get_tcp_session(tcp_hdr->src_port);
        if (tcp_session == NULL) {
            printf("Cannot find tcp session for SYN-ACK \n");
            return;
        }
        tcp_session->state = TCP_ESTABLISHED;
        // TODO: Packet conversion is not correct (seq, ack and port numbers aren't correctly copied over)
        debug_TCP("origional", tcp_hdr);
        struct tcp_hdr *ack_packet = init_tcp_packet();
        ack_packet->dst_port = htons(tcp_session->dst_port);
        ack_packet->flags = ACK;
        ack_packet->seq_num = tcp_hdr->ack_num;
        ack_packet->ack_num = tcp_hdr->ack_num + 1;
        debug_TCP("ack_packet", ack_packet);

        int ret = send_tcp(ack_packet, tcp_session->daddr);
        printf("SENT SYNACK! to %d and %d : %d\n",tcp_session->daddr, tcp_session->dst_port, ret);
        return;
    }
    if (tcp_hdr->flags & RST) {
        printf("RST flag is set\n");

        // If its a RST then we need to flag the socket as disconnected
        struct tcp_session *tcp_session = get_tcp_session(tcp_hdr->src_port);
        if (tcp_session == NULL) {
            printf("tcp_session is NULL\n");
            return;
        }
        tcp_session->state = TCP_CLOSED;
    }
    if (tcp_hdr->flags & PSH) {
        // TODO: Behavior for PSH flag
        printf("PSH flag is set\n");
    }

    if (tcp_hdr->flags & URG) {
        // TODO: Behavior for URG flag
        printf("URG flag is set\n");
    }

    free_sub(sub);
    assert(false);
}

// TODO: currently doesn't have any support for payloads 
// TODO: add busy loop that resends the packet until its acked.
// TODO: is not indiponent
// int tcp_tx(struct subuff *sub, uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, uint32_t seq_num, uint32_t ack_num, uint8_t flags, uint16_t window_size, uint16_t urgent_ptr, uint8_t *payload, uint16_t payload_len){
int tcp_tx(struct tcp_hdr* tcp_hdr_origional, uint32_t dst_ip){
    printf("Called tcp_tx!\n");
    
    struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    if (sub == NULL) {
        return -ENOMEM;
    }
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub_push(sub, TCP_HDR_LEN);

    sub->protocol = IPP_TCP;

    // Create a new tcp header
    struct tcp_hdr *tcp_hdr_sub = tcp_header(sub);
    if (tcp_hdr_sub == NULL) {
        // free_sub(sub);
        return -ENOMEM;
    }
    debug_TCP("packet:", tcp_hdr_origional);

    tcp_hdr_origional->data_offset = sizeof(struct tcp_hdr) / 4;
    memcpy(tcp_hdr_sub, tcp_hdr_origional, sizeof(struct tcp_hdr));

    tcp_hdr_sub->csum = 0;

    // Get the source ip by using route_lookup and then get the dev from the rtentry
    struct rtentry *rt = route_lookup(dst_ip);
    if (rt == NULL) {
        return -1;
    }
    uint32_t sourceip = rt->dev->addr;

    tcp_hdr_sub->csum = do_tcp_csum((uint8_t *)tcp_hdr_sub, sizeof(struct tcp_hdr), IPP_TCP, ntohl(sourceip), dst_ip);

    // TODO: Bug? 127.0.0.1 results in infinite ARP loop    
    int res = ip_output(htonl(dst_ip), sub);
    // This doesn't work, sub is permanently modified, need to copy it
    while (res == -EAGAIN){
        // wait for a bit and try again
        // TODO: avoid recursion (can't simply recall ip_output as it modifies the sub struct)
        sleep(1);   // TODO: avoid sleep
        res = tcp_tx(tcp_hdr_origional, dst_ip);
    }

    printf("Freeing struct @ %p\n", sub);
    printf("Freeing sub head at %p\n", sub->head);

    // Invalid pointer
    free_sub(sub);
    
    return res;
}

// Debug wrapper
extern int send_tcp(struct tcp_hdr* tcp_hdr, uint32_t dst_ip){
    printf("Called send_tcp!\n");
    return tcp_tx(tcp_hdr, dst_ip);
}