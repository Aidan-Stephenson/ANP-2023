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
// TODO: refactor sessions to keep track of payloads/packets -> new linked list of all unack'ed packets
struct tcp_session *get_tcp_session(uint16_t local_port, uint16_t remote_port, uint32_t daddr) {
    struct tcp_session *tcp_ses = TCP_SESSIONS;
    while (tcp_ses != NULL) {
        if (tcp_ses->src_port == local_port 
        && tcp_ses->dst_port == remote_port 
        && tcp_ses->daddr == daddr
        ) {
            return tcp_ses;
        }
        tcp_ses = tcp_ses->next;
    }
    printf("Couldn't find tcp session!\n");
    return NULL;
}


bool tcp_port_allocated(uint16_t port) {
    struct tcp_session *tcp_ses = TCP_SESSIONS;
    while (tcp_ses != NULL) {
        if (tcp_ses->src_port == port) {
            return true;
        }
        tcp_ses = tcp_ses->next;
    }
    return false;
}


struct tcp_hdr* init_tcp_packet() {
    struct tcp_hdr *packet = (struct tcp_hdr *)calloc(sizeof(struct tcp_hdr), 1);
    packet->seq_num = htonl(rand() % 100000);   // Could be bigger
    packet->ack_num = htonl(0);

    // https://canvas.vu.nl/courses/71468/discussion_topics/704951
    packet->src_port = htonl(rand() + 1000 % 0xff);
    while (tcp_port_allocated(packet->src_port)) {
        packet->src_port = htonl(rand() + 1000 % 0xff);
    }

    // TODO: look into
    packet->window_size = htons(1600); // Honestly don't know. THink we want to allocate it dynamically
    packet->urgent_ptr = htons(0); // We don't use it, might be worth looking into

    return packet;
}


void tcp_rx(struct subuff *sub){
    struct tcp_hdr *tcp_hdr = tcp_header(sub);
    struct tcp_session *tcp_session = get_tcp_session(tcp_hdr->dst_port, tcp_hdr->src_port, IP_HDR_FROM_SUB(sub)->saddr);
    if (tcp_session == NULL) {
        debug_TCP("Cannot find tcp session");
    }

    debug_TCP_packet("Received tcp_rx packet:", tcp_hdr);

    if (tcp_session == NULL) {
        if (tcp_hdr->flags & SYN) {
            // Implementation not needed:
            // 9) tcp.c:52 Client should not have to handle the case that a SYN message comes in. 
            debug_TCP("SYN flag is set");
        }
        goto end;
    }  
    
    // Source: https://www.researchgate.net/figure/TCP-Finite-State-Machine_fig1_260186294
    switch (tcp_session->state) {
        case TCP_LISTEN:
            // We don't have to implement
            break;
        case TCP_SYN_SENT:
            if (tcp_hdr->flags & SYN && tcp_hdr->flags & ACK) {
                debug_TCP("SYNACK flag is set");

                tcp_session->state = TCP_ESTABLISHED;
                
                struct tcp_hdr *ack_packet = init_tcp_packet();
                ack_packet->dst_port = tcp_hdr->src_port;
                ack_packet->src_port = tcp_hdr->dst_port;
                ack_packet->flags = ACK;
                ack_packet->seq_num = tcp_hdr->ack_num;
                ack_packet->ack_num = htonl(ntohl(tcp_hdr->seq_num) + 1);

                tcp_tx(ack_packet, ntohl(IP_HDR_FROM_SUB(sub)->saddr));
                free(ack_packet);

            } else if (tcp_hdr->flags & SYN) { // According to the tcp state machine it is valid to receive a SYN in this state
                tcp_session->state = TCP_SYN_RECEIVED;
                
                struct tcp_hdr *synack_packet = init_tcp_packet();
                synack_packet->dst_port = tcp_hdr->src_port;
                synack_packet->src_port = tcp_hdr->dst_port;
                synack_packet->flags = SYNACK;
                synack_packet->seq_num = tcp_hdr->ack_num;
                synack_packet->ack_num = htonl(ntohl(tcp_hdr->seq_num) + 1);
                
                // TODO: handle packet ack (stop resending)

                tcp_tx(synack_packet, ntohl(IP_HDR_FROM_SUB(sub)->saddr));
                free(synack_packet);
            }
            break;
        case TCP_SYN_RECEIVED:
             if (tcp_hdr->flags & SYN && tcp_hdr->flags & ACK) {
                tcp_session->state = TCP_SYN_RECEIVED;
                // TODO: handle packet ack (stop resending)
             }
            break;
        case TCP_ESTABLISHED:
            // Can receive a FIN
            break;
        case TCP_FIN_WAIT_1:
            break;
        case TCP_FIN_WAIT_2:
            break;
        case TCP_CLOSED:
            break;
        case TCP_CLOSE_WAIT:
            break;
        case TCP_CLOSING:
            break;
        case TCP_LAST_ACK:
            break;
        case TCP_TIME_WAIT:
            break;
    }

    end:
    free_sub(sub);
    // assert(false);
    return;
}

// TODO: currently doesn't have any support for payloads 
// TODO: start timer
// TODO: take a session argument, if null just send, if not null append packet to session
// int tcp_tx(struct subuff *sub, uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, uint32_t seq_num, uint32_t ack_num, uint8_t flags, uint16_t window_size, uint16_t urgent_ptr, uint8_t *payload, uint16_t payload_len){
int tcp_tx(struct tcp_hdr* tcp_hdr_origional, uint32_t dst_ip){
    debug_TCP("Entering tcp_tx!");
    
    // TODO: get TCP state

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
        return -EHOSTUNREACH;
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
        printf("recursing\n");
        res = tcp_tx(tcp_hdr_origional, dst_ip);
    }

    // Invalid pointer
    free_sub(sub);
    printf("Exiting tcp_tx with: %d\n", res);
    debug_TCP("Exiting tcp_tx: Packet sent");
    
    return res;
}


extern int send_tcp(struct tcp_hdr* tcp_hdr, uint32_t dst_ip){
    debug_TCP("Called send_tcp!");
    
    struct tcp_session *tcp_session = get_tcp_session(tcp_hdr->dst_port, tcp_hdr->src_port, ntohl(dst_ip));

    if (tcp_session == NULL) { 
        if (tcp_hdr->flags & SYN && TCP_SESSIONS == NULL) {
            // Init session list
            struct tcp_session *tcp_ses = (struct tcp_session *)malloc(TCP_SESSION_LEN);
            tcp_ses->src_port = tcp_hdr->src_port;
            tcp_ses->dst_port = tcp_hdr->dst_port;
            tcp_ses->daddr = ntohl(dst_ip); 
            tcp_ses->seq_num = tcp_hdr->seq_num;
            tcp_ses->ack_num = tcp_hdr->ack_num;
            tcp_ses->state = TCP_SYN_SENT;

            if (TCP_SESSIONS == NULL) {
                tcp_ses->next = TCP_SESSIONS;
                tcp_ses->prev = TCP_SESSIONS;
                TCP_SESSIONS = tcp_ses;
            } else {
                // Append to start of list
                tcp_ses->next = TCP_SESSIONS;
                TCP_SESSIONS->prev = tcp_ses;
                TCP_SESSIONS = tcp_ses;
            }

            return tcp_tx(tcp_hdr, dst_ip);   
        }

        return -1;
     }

    // Source: https://www.researchgate.net/figure/TCP-Finite-State-Machine_fig1_260186294
    // TODO: Append packet to session list
    // TODO: start timer, add a recursion level, if a threshold is reached tcp_tx will kill it
    switch (tcp_session->state) {
        case TCP_LISTEN:
            // We don't have to implement
            break;
        case TCP_SYN_SENT:
            if (tcp_hdr->flags & SYN) {
                return tcp_tx(tcp_hdr, dst_ip);   
            }
            break;
        case TCP_SYN_RECEIVED:
            break;
        case TCP_ESTABLISHED:
            break;
        case TCP_FIN_WAIT_1:
            break;
        case TCP_FIN_WAIT_2:
            break;
        case TCP_CLOSED:
            break;
        case TCP_CLOSE_WAIT:
            break;
        case TCP_CLOSING:
            break;
        case TCP_LAST_ACK:
            break;
        case TCP_TIME_WAIT:
            break;
    }

    return 0;
}