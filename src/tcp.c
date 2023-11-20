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
struct tcp_ses *get_tcp_session(uint16_t dst_port) {
    struct list_head *item;
    struct tcp_ses *tcp_ses = TCP_SESSIONS;
    while (tcp_ses != NULL) {
        if (tcp_ses->dst_port == dst_port) {
            return tcp_ses;
        }
        tcp_ses = tcp_ses->next;
    }
    
    return NULL;

}

void tcp_rx(struct subuff *sub){
    printf("Called tcp_rx!\n");

    //FIXME: implement your TCP packet processing implementation here
    // Essentially if its SYN then we need to send a SYN ACK
    // If its an SYN ACK then we need to send an ACK and flag the socket as connected
    // If its an ACK then we need to flag the socket as connected
    // If its a FIN then we need to send an ACK and flag the socket as disconnected
    // If its any other flag then we need to send an ACK, and if the socket is connected then we need to send the data to the application (somehow)
    // If its a RST then we need to flag the socket as disconnected
    
    struct tcp_hdr *tcp_hdr = tcp_header(sub);

    debug_TCP("packet:", tcp_hdr);

    if (tcp_hdr->flags & FIN) {
        // Behavior for FIN flag
        printf("FIN flag is set\n");
    }
    if (tcp_hdr->flags & SYN && !(tcp_hdr->flags & ACK)) {
    // Essentially if its SYN, BUT NOT SYN_ACK, then we need to send a SYN ACK

        //SYN ACK Attempt
        struct tcp_hdr syn_ack_packet;
        //syn_ack_packet.src_port = htons(src_port); // TODO: allocate port
        syn_ack_packet.dst_port = htons(tcp_hdr->src_port); //TODO: FIND PORT
        syn_ack_packet.seq_num = htonl(0);  //TODO: server's initial sequence number should be randomly generated
        syn_ack_packet.ack_num = htonl(ntohl(tcp_hdr->seq_num) + 1);  //CAUTION!! conversion might be wrong //it should be seq_num from syn packet + 1
        syn_ack_packet.flags = SYNACK; //SYNACK flag is defined as SYN+ACK
        syn_ack_packet.window_size = htons(1600); // Honestly don't know  
        syn_ack_packet.urgent_ptr = htons(0); // We don't use it


        //TODO:SEND THIS PACKET BACK TO HOST (tcp_tx)???????
        struct tcp_ses *tcp_session = get_tcp_session(tcp_hdr->src_port);
        if (tcp_session == NULL) {
            printf("tcp_session is NULL\n");
            return;
        }
        // Set the tcp session state to TCP_SYN_RCVD
        tcp_session->state = TCP_SYN_RECEIVED;

        


        // return ack

        printf("SYN flag is set\n");
    }
    if (tcp_hdr->flags & SYN && tcp_hdr->flags & ACK) {
        struct tcp_ses *tcp_session = get_tcp_session(tcp_hdr->src_port);
        if (tcp_session == NULL) {
            printf("tcp_session is NULL\n");
            return;
        }
        // Iterate through tcp sessions, see if dst_h + dst_port + src_h + src_port match -> set tcp session state to TCP_ESTABLISHED 
        tcp_session->state = TCP_ESTABLISHED;

        struct tcp_hdr *syc_packet = malloc(sizeof(struct tcp_hdr));
        // syc_packet->src_port = htons(src_port); // TODO: allocate port
        syc_packet->dst_port = htons(tcp_session->dst_port);
        syc_packet->seq_num = htonl(0); //TODO: this cant be 0 all the time because we need to assume multiple connections
        syc_packet->ack_num = htonl(0);  //TODO: same as above
        syc_packet->flags = ACK;
        syc_packet->window_size = htons(1600); // Honestly don't know  //LUKA: SYN packet has no payload, so window size is put as 1, referred to as a ghost Byte 
        syc_packet->urgent_ptr = htons(0); // We don't use it

        int ret = send_tcp(syc_packet, tcp_session->daddr);
        printf("SENT ACK! to %d and %d : %d\n",tcp_session->daddr, tcp_session->dst_port, ret);
        // return ack

        printf("SYN flag is set\n");
    }
    if (tcp_hdr->flags & RST) {
        // If its a RST then we need to flag the socket as disconnected
        struct tcp_ses *tcp_session = get_tcp_session(tcp_hdr->src_port);
        if (tcp_session == NULL) {
            printf("tcp_session is NULL\n");
            return;
        }
        tcp_session->state = TCP_CLOSED;

        printf("RST flag is set\n");
    }
    if (tcp_hdr->flags & PSH) {
        // Behavior for PSH flag
        printf("PSH flag is set\n");
    }

    if (tcp_hdr->flags & URG) {
        // Behavior for URG flag
        printf("URG flag is set\n");
    }

    free_sub(sub);
    sleep(10);
    assert(false);
}

// TODO: currently doesn't have any support for payloads 
// int tcp_tx(struct subuff *sub, uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, uint32_t seq_num, uint32_t ack_num, uint8_t flags, uint16_t window_size, uint16_t urgent_ptr, uint8_t *payload, uint16_t payload_len){
int tcp_tx(struct tcp_hdr* tcp_hdr, uint32_t dst_ip){

    printf("Called tcp_tx!\n");
    
    struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    
    if (sub == NULL) {
        return -ENOMEM;
    }

    sub->protocol = IPP_TCP;

    // Create a new tcp header
    struct tcp_hdr *tcp_hdr_sub = (struct tcp_hdr *)(sub->head + ETH_HDR_LEN + IP_HDR_LEN);
    if (tcp_hdr_sub == NULL) {
        return -ENOMEM;
    }
    debug_TCP("packet:", tcp_hdr);

    tcp_hdr->data_offset = sizeof(struct tcp_hdr) / 4;
    memcpy(tcp_hdr_sub, tcp_hdr, sizeof(struct tcp_hdr));
    //Push the tcp header
    debug_TCP("packet_copy:", tcp_hdr_sub);

    // // Set the fields
    // tcp_hdr->src_port = htons(src_port);
    // tcp_hdr->dst_port = htons(dst_port);
    // tcp_hdr->seq_num = htonl(seq_num);
    // tcp_hdr->ack_num = htonl(ack_num);
    // tcp_hdr->flags = flags;
    // tcp_hdr->window_size = htons(window_size);
    // tcp_hdr->urgent_ptr = htons(urgent_ptr);


    // // Push the payload
    // if (payload != NULL) {
    //     if (sub_push(sub, payload_len) == NULL) {
    //         return -ENOMEM;
    //     }
    //     memcpy(sub->data, payload, payload_len);
    // }
    // Calculate the checksum
    tcp_hdr_sub->csum = 0;

    // Get the source ip by using route_lookup and then get the dev from the rtentry
    struct rtentry *rt = route_lookup(dst_ip);
    if (rt == NULL) {
        return -1;
    }
    uint32_t sourceip = rt->dev->addr;

    tcp_hdr_sub->csum = do_tcp_csum((uint8_t *)tcp_hdr_sub, sizeof(struct tcp_hdr), IPP_TCP, ntohl(sourceip), dst_ip);
    // Send the packet
    // TODO: Bug? 127.0.0.1 results in infinite ARP loop
    int res = ip_output(htonl(dst_ip), sub);
    while (res == -EAGAIN){
        // wait for a bit and try again
        printf("Waiting again :(\n");
        sleep(1);
        res = ip_output(htonl(dst_ip), sub);
    }
    printf("tcp_tx result: %i\n", res);

    free_sub(sub);
    
    return res;
}

extern int send_tcp(struct tcp_hdr* tcp_hdr, uint32_t dst_ip){
    printf("Called send_tcp!\n");
    return tcp_tx(tcp_hdr, dst_ip);
}