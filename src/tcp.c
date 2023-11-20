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
    

        // return ack //IDK what this comment means????
        printf("SYN flag is set\n");
    }
    if (tcp_hdr->flags & SYN && tcp_hdr->flags & ACK) {
        // Iterate through tcp sessions, see if dst_h + dst_port + src_h + src_port match -> set tcp session state to TCP_ESTABLISHED 
        // return ack
        printf("SYN flag is set\n");
    }
    if (tcp_hdr->flags & RST) {
        // If its a RST then we need to flag the socket as disconnected
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
    assert(false);
}

// TODO: currently doesn't have any support for payloads 
// int tcp_tx(struct subuff *sub, uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, uint32_t seq_num, uint32_t ack_num, uint8_t flags, uint16_t window_size, uint16_t urgent_ptr, uint8_t *payload, uint16_t payload_len){
int tcp_tx(struct tcp_hdr* tcp_hdr, uint32_t dst_ip){

    printf("Called tcp_tx!\n");

    struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    if (sub == NULL) {
        return -ENOMEM;
    }

    // Create a new tcp header
    struct tcp_hdr *tcp_hdr_sub = (struct tcp_hdr *)sub_push(sub, sizeof(struct tcp_hdr));
    if (tcp_hdr == NULL) {
        return -ENOMEM;
    }

    memcpy(tcp_hdr, tcp_hdr_sub, sizeof(struct tcp_hdr));

    // // Set the fields
    // tcp_hdr->src_port = htons(src_port);
    // tcp_hdr->dst_port = htons(dst_port);
    // tcp_hdr->seq_num = htonl(seq_num);
    // tcp_hdr->ack_num = htonl(ack_num);
    // tcp_hdr->flags = flags;
    // tcp_hdr->window_size = htons(window_size);
    // tcp_hdr->urgent_ptr = htons(urgent_ptr);

    // Calculate the offset
    tcp_hdr->data_offset = sizeof(struct tcp_hdr) / 4;

    // // Push the payload
    // if (payload != NULL) {
    //     if (sub_push(sub, payload_len) == NULL) {
    //         return -ENOMEM;
    //     }
    //     memcpy(sub->data, payload, payload_len);
    // }
    // Calculate the checksum
    tcp_hdr_sub->checksum = 0;

    // Get the source ip by using route_lookup and then get the dev from the rtentry
    struct rtentry *rt = route_lookup(dst_ip);
    if (rt == NULL) {
        return -1;
    }
    uint32_t sourceip = rt->dev->addr;

    tcp_hdr_sub->checksum = htons(do_tcp_csum((uint8_t *)tcp_hdr_sub, sizeof(struct tcp_hdr), IPPROTO_TCP, htonl(sourceip), htonl(dst_ip)));
    // Send the packet
    
    return ip_output(dst_ip, sub);
        // assert(false);
}

extern int send_tcp(struct tcp_hdr* tcp_hdr, uint32_t dst_ip){
    printf("Called send_tcp!\n");
    return tcp_tx(tcp_hdr, dst_ip);
}