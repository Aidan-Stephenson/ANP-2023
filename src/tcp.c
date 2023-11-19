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

    // Get packet type -> tcp flags
    // if syn->
        // send syn ack
    // if syn-ack -> 
        // Iterate through tcp sessions, see if dst_h + dst_port + src_h + src_port match -> set tcp session 
        // return ack
    // if rst ->
        // disconnect
    // otherwise drop

    free_sub(sub);
    assert(false);
}

// Returns the number of bytes 
// TODO: refactor, take tcp header + payload, create sub, send
int tcp_tx(struct subuff *sub, uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, uint32_t seq_num, uint32_t ack_num, uint8_t flags, uint16_t window_size, uint16_t urgent_ptr, uint8_t *payload, uint16_t payload_len){
    printf("Called tcp_tx!\n");

    // if no sub is provided, create one
    if (sub == NULL) {
        sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + payload_len);
        if (sub == NULL) {
            return -ENOMEM;
        }
    }

    // Create a new tcp header
    struct tcp_hdr *tcp_hdr = (struct tcp_hdr *)sub_push(sub, sizeof(struct tcp_hdr));
    if (tcp_hdr == NULL) {
        return -ENOMEM;
    }

    // Set the fields
    tcp_hdr->src_port = htons(src_port);
    tcp_hdr->dst_port = htons(dst_port);
    tcp_hdr->seq_num = htonl(seq_num);
    tcp_hdr->ack_num = htonl(ack_num);
    tcp_hdr->flags = flags;
    tcp_hdr->window_size = htons(window_size);
    tcp_hdr->urgent_ptr = htons(urgent_ptr);

    // Calculate the offset
    tcp_hdr->data_offset = sizeof(struct tcp_hdr) / 4;

    // Push the payload
    if (payload != NULL) {
        if (sub_push(sub, payload_len) == NULL) {
            return -ENOMEM;
        }
        memcpy(sub->data, payload, payload_len);
    }
    // Calculate the checksum
    tcp_hdr->checksum = 0;

    // Get the source ip by using route_lookup and then get the dev from the rtentry
    struct rtentry *rt = route_lookup(dst_ip);
    if (rt == NULL) {
        return -1;
    }
    uint32_t sourceip = rt->dev->addr;

    tcp_hdr->checksum = htons(do_tcp_csum((uint8_t *)tcp_hdr, sizeof(struct tcp_hdr) + payload_len, IPPROTO_TCP, htonl(sourceip), htonl(dst_ip)));
    // Send the packet
    
    return ip_output(dst_ip, sub);
        // assert(false);

}
