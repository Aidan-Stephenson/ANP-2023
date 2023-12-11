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


struct tcp_pkt *get_tcp_packet(struct tcp_session *tcp_ses, uint32_t ack_num) {
    ack_num = htonl(ntohl(ack_num) - 1);
    struct tcp_pkt *tcp_packet = tcp_ses->packets;
    while (tcp_packet != NULL) {
        if (tcp_packet->hdr->seq_num == ack_num) {
            return tcp_packet;
        }
        tcp_packet = tcp_packet->next;
    }

    return NULL;
}

void free_packet(struct tcp_pkt *tcp_packet) {
     if (tcp_packet != NULL) {
        debug_TCP("Packet acked, stopping retrans");
        if (tcp_packet->timer != NULL) {
            timer_cancel(tcp_packet->timer);
        }
        if (tcp_packet->next != NULL) {
            tcp_packet->next->prev = tcp_packet->prev;
        }
        if (tcp_packet->prev != NULL) {
            tcp_packet->prev->next = tcp_packet->next;
        }
        // TODO: Possible bug?
        free(tcp_packet);
    } else {
        debug_TCP("Couldn't find packet");
    }
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


struct tcp_hdr* init_tcp_hdr() {
    struct tcp_hdr *packet = (struct tcp_hdr *)calloc(sizeof(struct tcp_hdr), 1);
    packet->seq_num = htonl(rand() % 100000);   // Could be bigger
    packet->ack_num = htonl(0);

    // https://canvas.vu.nl/courses/71468/discussion_topics/704951
    // TODO: init rand
    // TODO: adjust formula

    packet->src_port = htonl(rand() + 1000 % 0xff);
    while (tcp_port_allocated(packet->src_port)) {
        packet->src_port = htonl(rand() + 1000 % 0xff);
    }

    // TODO: look into -> make sure we don't overflow received window
    packet->window_size = htons(64240); // Honestly don't know. THink we want to allocate it dynamically
    packet->urgent_ptr = htons(0); // We don't use it, might be worth looking into

    return packet;
}


struct tcp_pkt* init_tcp_packet() {
    struct tcp_hdr* tcp_hdr = init_tcp_hdr();
    struct tcp_pkt* tcp_packet = (struct tcp_pkt *)calloc(sizeof(struct tcp_pkt), 1);
    tcp_packet->hdr = tcp_hdr;
    
    return tcp_packet;
}

// TODO: decrement sent by ack'ed payload length to keep track of window
void tcp_rx(struct subuff *sub){
    struct tcp_hdr *tcp_hdr = tcp_header(sub);
    struct tcp_session *tcp_session = get_tcp_session(tcp_hdr->dst_port, tcp_hdr->src_port, ntohl(IP_HDR_FROM_SUB(sub)->saddr));
    if (tcp_session == NULL) {
        debug_TCP("Cannot find tcp session in rx");
    }

    debug_TCP_packet("Received tcp_rx packet:", tcp_hdr);

    if (tcp_session == NULL) {
        debug_TCP("Could not find TCP session for received packet");
        if (tcp_hdr->flags & SYN) {
            // Implementation not needed:
            // 9) tcp.c:52 Client should not have to handle the case that a SYN message comes in. 
            debug_TCP("SYN flag is set");
        }
        goto end;
    }  

    if (tcp_session->state == TCP_SYN_SENT || tcp_session->state == TCP_SYN_RECEIVED) {}  // When a connection is being initiated we still need to establish sequences.
    // TODO: we probably have an issue in either ack retransmission or in acks in general, the first ack is fine the rest is not.
    // Retransmit ack
    else if (tcp_hdr->seq_num < tcp_session->ack_num) {
        printf("Resending ACK\n");
        struct tcp_pkt* ack_packet = init_tcp_packet();
        ack_packet->hdr->dst_port = tcp_hdr->src_port;
        ack_packet->hdr->src_port = tcp_hdr->dst_port;
        ack_packet->hdr->flags = ACK;
        ack_packet->hdr->seq_num = tcp_hdr->ack_num;
        ack_packet->hdr->ack_num = htonl(ntohl(tcp_hdr->seq_num) + sub->dlen + 1);
        ack_packet->daddr = IP_HDR_FROM_SUB(sub)->saddr;
        
        // tcp_tx(ack_packet);
        free(ack_packet->hdr);
        free(ack_packet);
    }
    // Ignore, its out of sequence
    else if (tcp_hdr->seq_num > htonl(ntohl(tcp_session->ack_num) + 1)) {     
        printf("Ignoring seq_num: %d | ack_num: %d \n", ntohl(tcp_hdr->seq_num), ntohl(tcp_session->ack_num)); 
        goto end; 
    }
    // If the ack flag is present, we need to stop retransmitting whatever packet
    else if (tcp_hdr->flags & ACK ) {
        printf("Handling ACK\n");
        struct tcp_pkt *tcp_packet = get_tcp_packet(tcp_session, tcp_hdr->ack_num);
        if (tcp_packet != NULL) { 
            if (tcp_session->packets == tcp_packet) {
                tcp_session->packets = tcp_packet->next;
            }
            free_packet(tcp_packet);
        }
    }

    // TODO: ack, when we do we ack the previous ack + payload size 
    // Source: https://www.researchgate.net/figure/TCP-Finite-State-Machine_fig1_260186294
    switch (tcp_session->state) {
        case TCP_LISTEN:
            // We don't have to implement
            break;
        case TCP_SYN_SENT:
            if (tcp_hdr->flags & SYN && tcp_hdr->flags & ACK) {
                debug_TCP("SYNACK flag is set");

                tcp_session->state = TCP_ESTABLISHED;
                tcp_session->ack_num = tcp_hdr->seq_num;

                struct tcp_pkt* ack_packet = init_tcp_packet();
                ack_packet->hdr->dst_port = tcp_hdr->src_port;
                ack_packet->hdr->src_port = tcp_hdr->dst_port;
                ack_packet->hdr->flags = ACK;
                ack_packet->hdr->seq_num = tcp_hdr->ack_num;
                ack_packet->hdr->ack_num = htonl(ntohl(tcp_hdr->seq_num) + 1);
                ack_packet->daddr = IP_HDR_FROM_SUB(sub)->saddr;

                struct tcp_pkt *tcp_packet = get_tcp_packet(tcp_session, tcp_hdr->ack_num);
                if (tcp_packet != NULL) { 
                    if (tcp_session->packets == tcp_packet) {
                        tcp_session->packets = tcp_packet->next;
                    }
                    free_packet(tcp_packet);
                }
                printf("ACKING\n");
                tcp_tx(ack_packet);
                free_packet(ack_packet);
            } else if (tcp_hdr->flags & SYN) { // According to the tcp state machine it is valid to receive a SYN in this state
                tcp_session->state = TCP_SYN_RECEIVED;
                tcp_session->ack_num = tcp_hdr->seq_num;

                struct tcp_pkt* synack_packet = init_tcp_packet();
                synack_packet->hdr->dst_port = tcp_hdr->src_port;
                synack_packet->hdr->src_port = tcp_hdr->dst_port;
                synack_packet->hdr->flags = SYNACK;
                synack_packet->hdr->seq_num = tcp_hdr->ack_num;
                synack_packet->hdr->ack_num = htonl(ntohl(tcp_hdr->seq_num) + 1);
                
                struct tcp_pkt *tcp_packet = get_tcp_packet(tcp_session, tcp_hdr->ack_num);
                if (tcp_packet != NULL) {
                    if (tcp_session->packets == tcp_packet) {
                        tcp_session->packets = tcp_packet->next;
                    }
                    free_packet(tcp_packet);
                }

                synack_packet->daddr = ntohl(IP_HDR_FROM_SUB(sub)->saddr);

                tcp_tx(synack_packet);
                free_packet(synack_packet);
            }
            break;
        case TCP_SYN_RECEIVED:
            break;
        case TCP_ESTABLISHED:
            if (false){
                // Can receive a FIN
            } else if (tcp_hdr->flags & ACK && IP_HDR_FROM_SUB(sub)->len - TCP_HDR_LEN - IP_HDR_LEN == 0){
                printf("Empty ACK\n");
            }
            else {
                // Receive data
                printf("TCP_ESTABLISHED: ACKing\n");
                struct tcp_pkt* ack_packet = init_tcp_packet();
                ack_packet->hdr->dst_port = tcp_hdr->src_port;
                ack_packet->hdr->src_port = tcp_hdr->dst_port;
                ack_packet->hdr->flags = ACK;
                ack_packet->hdr->seq_num = htonl(ntohl(tcp_session->seq_num) + 1);
                ack_packet->hdr->ack_num = htonl(ntohl(tcp_session->ack_num) + IP_HDR_FROM_SUB(sub)->len - TCP_HDR_LEN - IP_HDR_LEN + 1);
                ack_packet->daddr = IP_HDR_FROM_SUB(sub)->saddr;
                
                tcp_session->seq_num = ack_packet->hdr->seq_num;
                tcp_session->ack_num = ack_packet->hdr->ack_num;
                // TODO: Update session ack_num
                // TODO: add data to buffer
                tcp_tx(ack_packet);
                free(ack_packet->hdr);
                free(ack_packet);
            }
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
    return;
}

// This thing needs does one thing and one thing only, send tcp packets, session management is handled
// externally. The one exception to this is the recurse threshold which is used to kill a timer.
int tcp_tx(struct tcp_pkt* tcp_packet){
    debug_TCP("Entering tcp_tx!");
    tcp_packet->retries += 1;

    if (tcp_packet->retries > TCP_RETRIES1) {
        // TODO: deal with too many retries
    }

    // Get the source ip by using route_lookup and then get the dev from the rtentry
    struct rtentry *rt = route_lookup(tcp_packet->daddr);
    if (rt == NULL) {
        debug_TCP("Exiting tcp_tx: failed to find route to host");
        return -EHOSTUNREACH;
    }

    int res = -EAGAIN;
    struct tcp_hdr* tcp_hdr_origional = tcp_packet->hdr;
    struct subuff *sub = NULL;
    struct tcp_hdr *tcp_hdr_sub = NULL;
    uint32_t sourceip = rt->dev->addr;
    while (res == -EAGAIN) {
        sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + tcp_packet->payload_size);
        if (sub == NULL) {
            return -ENOMEM;
        }
        sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + tcp_packet->payload_size);
        sub_push(sub, TCP_HDR_LEN + tcp_packet->payload_size);

        sub->protocol = IPP_TCP;

        // Create a new tcp header
        tcp_hdr_sub = tcp_header(sub);

        debug_TCP_packet("packet:", tcp_hdr_origional);

        tcp_hdr_origional->data_offset = sizeof(struct tcp_hdr) / 4;
        memcpy(tcp_hdr_sub, tcp_hdr_origional, sizeof(struct tcp_hdr)); // Add TCP header
        memcpy(tcp_hdr_sub + 1, tcp_packet->buf, tcp_packet->payload_size); // Add TCP payload
        tcp_hdr_sub->csum = 0;
        tcp_hdr_sub->csum = do_tcp_csum((uint8_t *)tcp_hdr_sub, sizeof(struct tcp_hdr) + tcp_packet->payload_size, IPP_TCP, ntohl(sourceip), htonl(tcp_packet->daddr));

        // TODO: Bug? 127.0.0.1 results in infinite ARP loop    
        res = ip_output(tcp_packet->daddr, sub);
        free_sub(sub);
        sleep(1);
    }
    
    printf("Exiting tcp_tx with: %d\n", res);
    debug_TCP("Exiting tcp_tx: Packet sent");
    return res;
}

extern int send_tcp(struct tcp_pkt* tcp_packet, uint32_t dst_ip){
    debug_TCP("Called send_tcp!");
    struct tcp_hdr* tcp_hdr = tcp_packet->hdr;
    debug_TCP_packet("sending payload", tcp_hdr);
    struct tcp_session *tcp_session = get_tcp_session(tcp_hdr->src_port, tcp_hdr->dst_port, dst_ip);

    if (tcp_session == NULL) { 
        if (tcp_hdr->flags & SYN && TCP_SESSIONS == NULL) {
            // Init session list
            struct tcp_session *tcp_ses = (struct tcp_session *)malloc(TCP_SESSION_LEN);
            tcp_ses->src_port = tcp_hdr->src_port;
            tcp_ses->dst_port = tcp_hdr->dst_port;
            tcp_ses->daddr = dst_ip; 
            tcp_ses->seq_num = tcp_hdr->seq_num;
            tcp_ses->ack_num = tcp_hdr->ack_num;
            tcp_ses->state = TCP_SYN_SENT;

            if (TCP_SESSIONS == NULL) {
                debug_TCP("Created tcp sessions");
                tcp_ses->next = TCP_SESSIONS;
                tcp_ses->prev = TCP_SESSIONS;
                TCP_SESSIONS = tcp_ses;
            } else {
                debug_TCP("Appended to sessions");
                // Append to start of list
                tcp_ses->next = TCP_SESSIONS;
                TCP_SESSIONS->prev = tcp_ses;
                TCP_SESSIONS = tcp_ses;
            }

            tcp_packet->hdr = tcp_hdr;
            tcp_packet->retries = 0;
            tcp_packet->daddr = htonl(dst_ip);
            tcp_packet->timer = timer_add(TCP_ACK_TIMEOUT, (void *)tcp_tx, tcp_packet);
            tcp_ses->packets = tcp_packet;

            return tcp_tx(tcp_packet);   
        }
        return -EINVAL;
     }

    // Source: https://www.researchgate.net/figure/TCP-Finite-State-Machine_fig1_260186294
    switch (tcp_session->state) {
        case TCP_LISTEN:
            // We don't have to implement
            break;
        case TCP_SYN_SENT:
            if (tcp_hdr->flags & SYN) {
                debug_TCP("Session already initiated");
                return -EINVAL;   
            }
            break;
        case TCP_SYN_RECEIVED:
            break;
        case TCP_ESTABLISHED:
            debug_TCP("Established sending data");
            tcp_packet->hdr->seq_num = htonl(ntohl(tcp_session->seq_num) + 1);
            tcp_packet->hdr->ack_num = htonl(ntohl(tcp_session->ack_num) + 1);
            tcp_packet->hdr->flags = ACK;
            tcp_packet->daddr = htonl(dst_ip);
            // tcp_packet->timer = timer_add(TCP_ACK_TIMEOUT, (void *)tcp_tx, tcp_packet); // Alternative timeout?
            tcp_session->seq_num = htonl(ntohl(tcp_session->seq_num) + tcp_packet->payload_size);

            // TODO: chop data into chunks and send it on
            return tcp_tx(tcp_packet);
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

    return -EINVAL;
}