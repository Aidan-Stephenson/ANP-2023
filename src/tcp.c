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
// TODO: refactor sessions to keep track of payloads/packets
struct tcp_session *get_tcp_session(uint16_t local_port, uint16_t remote_port, uint32_t daddr) {
    struct tcp_session *tcp_ses = TCP_SESSIONS;
    while (tcp_ses != NULL) {
        if (tcp_ses->src_port == local_port 
        // && tcp_ses->dst_port == remote_port 
        // && tcp_ses->daddr == daddr
        ) {
            return tcp_ses;
        }
        tcp_ses = tcp_ses->next;
    }
    
    return NULL;
}


struct tcp_hdr* init_tcp_packet() {
    struct tcp_hdr *packet = (struct tcp_hdr *)calloc(sizeof(struct tcp_hdr), 1);
    // TODO: Randomize
    // packet->seq_num = rand();
    packet->seq_num = htonl(0);
    packet->ack_num = htonl(0);

    // TODO: allocate port
    // https://canvas.vu.nl/courses/71468/discussion_topics/704951
    // packet->src_port = htons(src_port);

    // TODO: look into
    packet->window_size = htons(1600); // Honestly don't know. THink we want to allocate it dynamically
    packet->urgent_ptr = htons(0); // We don't use it, might be worth looking into

    return packet;
}


// TODO: check TCP session state -> flags only make sense in certain contexts
// TODO: refactor if tree to el/if -> flag combinations
void tcp_rx(struct subuff *sub){
    struct tcp_hdr *tcp_hdr = tcp_header(sub);

    debug_TCP_packet("Received tcp_rx packet:", tcp_hdr);

    if (tcp_hdr->flags & SYN && tcp_hdr->flags & ACK) {
        debug_TCP("SYNACK flag is set");
        
        struct tcp_session *tcp_session = get_tcp_session(tcp_hdr->dst_port, tcp_hdr->src_port, IP_HDR_FROM_SUB(sub)->saddr);
        if (tcp_session == NULL) {
            debug_TCP("Cannot find tcp session for SYN-ACK");
            return;
        }
        tcp_session->state = TCP_ESTABLISHED;
        
        struct tcp_hdr *ack_packet = init_tcp_packet();
        ack_packet->dst_port = tcp_hdr->src_port;
        ack_packet->flags = ACK;
        ack_packet->seq_num = tcp_hdr->ack_num;
        ack_packet->ack_num = htonl(ntohl(tcp_hdr->seq_num) + 1);

        tcp_tx(ack_packet, tcp_session->daddr);

        return;
    } 
    
    if (tcp_hdr->flags & SYN && tcp_hdr->flags & ECE) {
        debug_TCP("SYN ECE flag set");
        // TODO: ECESYN flag
    }
    
    if (tcp_hdr->flags & ECE) {
        debug_TCP("ECE flag set");
        // TODO: ECE flag
    }
    
    if (tcp_hdr->flags & CWR) {
        debug_TCP("CWR flag set");
        // TODO: CWR flag
    }
    
    if (tcp_hdr->flags & FIN) {
        // TODO: FIN flag
        debug_TCP("FIN flag is set");
    }
    
    if (tcp_hdr->flags & SYN) {
        // Implementation not needed:
        // 9) tcp.c:52 Client should not have to handle the case that a SYN message comes in. 
        debug_TCP("SYN flag is set");
    }
    
    if (tcp_hdr->flags & RST) {
        debug_TCP("RST flag is set");

        // If its a RST then we need to flag the socket as disconnected
        struct tcp_session *tcp_session = get_tcp_session(tcp_hdr->dst_port, tcp_hdr->src_port, IP_HDR_FROM_SUB(sub)->saddr);
        if (tcp_session == NULL) {
            debug_TCP("Cannot find tcp session for RST");
            return;
        }
        tcp_session->state = TCP_CLOSED;

        // TODO: cleanup session?
    } 
    
    if (tcp_hdr->flags & PSH) {
        // TODO: Behavior for PSH flag
        // Implementation is not needed: https://canvas.vu.nl/courses/71468/discussion_topics/708533
        debug_TCP("PSH flag is set");
    } 
    
    if (tcp_hdr->flags & ACK) {
        // TODO: Behavior for ACK flag
        debug_TCP("ACK flag is set");
    } else if (tcp_hdr->flags & URG) {
        // TODO: Behavior for URG flag
        debug_TCP("URG flag is set");
    } else {
        debug_TCP("UNKNOWN FLAG");
    }

    free_sub(sub);
    assert(false);
}

// TODO: currently doesn't have any support for payloads 
// TODO: add busy loop that resends the packet until its acked.
// TODO: is not indiponent
// int tcp_tx(struct subuff *sub, uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, uint32_t seq_num, uint32_t ack_num, uint8_t flags, uint16_t window_size, uint16_t urgent_ptr, uint8_t *payload, uint16_t payload_len){
int tcp_tx(struct tcp_hdr* tcp_hdr_origional, uint32_t dst_ip){
    debug_TCP("Entering tcp_tx!");
    
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
        free_sub(sub);
        debug_TCP("Exiting tcp_tx: failed to create tcp header");
        return -ENOMEM;
    }

    debug_TCP_packet("packet:", tcp_hdr_origional);

    tcp_hdr_origional->data_offset = sizeof(struct tcp_hdr) / 4;
    memcpy(tcp_hdr_sub, tcp_hdr_origional, sizeof(struct tcp_hdr));

    tcp_hdr_sub->csum = 0;

    // Get the source ip by using route_lookup and then get the dev from the rtentry
    struct rtentry *rt = route_lookup(dst_ip);
    if (rt == NULL) {
        debug_TCP("Exiting tcp_tx: failed to find route to host");
        // TODO: use proper error code
        return -1;
    }
    uint32_t sourceip = rt->dev->addr;

    tcp_hdr_sub->csum = do_tcp_csum((uint8_t *)tcp_hdr_sub, sizeof(struct tcp_hdr), IPP_TCP, ntohl(sourceip), dst_ip);

    // TODO: Bug? 127.0.0.1 results in infinite ARP loop    
    int res = ip_output(htonl(dst_ip), sub);
    while (res == -EAGAIN){
        // wait for a bit and try again
        // TODO: avoid recursion (can't simply recall ip_output as it modifies the sub struct)
        // TODO: avoid sleep -> use timer object
        sleep(1);
        res = tcp_tx(tcp_hdr_origional, dst_ip);
    }

    // Invalid pointer
    free_sub(sub);
    
    debug_TCP("Exiting tcp_tx: Packet sent");
    
    return res;
}

// TODO: enforce protocol spec (don't send SYN when its already estabished, etc)
extern int send_tcp(struct tcp_hdr* tcp_hdr, uint32_t dst_ip){
    debug_TCP("Called send_tcp!");
    return tcp_tx(tcp_hdr, dst_ip);
}