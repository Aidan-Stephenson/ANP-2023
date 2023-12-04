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

#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H

#include "systems_headers.h"

//tcp state machine https://www.nsnam.org/docs/release/3.27/models/html/_images/tcp-state-machine.png
enum tcp_states {
    TCP_LISTEN, /* represents waiting for a connection request from any remote
                   TCP and port. */
    TCP_SYN_SENT, /* represents waiting for a matching connection request
                     after having sent a connection request. */
    TCP_SYN_RECEIVED, /* represents waiting for a confirming connection
                         request acknowledgment after having both received and sent a
                         connection request. */
    TCP_ESTABLISHED, /* represents an open connection, data received can be
                        delivered to the user.  The normal state for the data transfer phase
                        of the connection. */
    TCP_FIN_WAIT_1, /* represents waiting for a connection termination request
                       from the remote TCP, or an acknowledgment of the connection
                       termination request previously sent. */
    TCP_FIN_WAIT_2, /* represents waiting for a connection termination request
                       from the remote TCP. */
    TCP_CLOSED, /* represents no connection state at all. */
    TCP_CLOSE_WAIT, /* represents waiting for a connection termination request
                       from the local user. */
    TCP_CLOSING, /* represents waiting for a connection termination request
                    acknowledgment from the remote TCP. */
    TCP_LAST_ACK, /* represents waiting for an acknowledgment of the
                     connection termination request previously sent to the remote TCP
                     (which includes an acknowledgment of its connection termination
                     request). */
    TCP_TIME_WAIT, /* represents waiting for enough time to pass to be sure
                      the remote TCP received the acknowledgment of its connection
                      termination request. */
};

// https://rsjakob.gitbooks.io/iqt-network-programming/osi-layer-4/tcp-header.html
// FIXME: define a TCP header format

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;

    uint8_t reserved:4;
    uint8_t data_offset:4;

    uint8_t flags;
    //checksum
    uint16_t window_size; 
    uint16_t csum;
    uint16_t urgent_ptr; // We don't support this, but its part of the header
} __attribute__((packed));

#include "subuff.h" // Custom, to avoid warnings
void tcp_rx(struct subuff *sub);

/* This segment is not part of the given framework and most likely to contain bugs */
#include "ethernet.h"
#include "ip.h"
#include "utilities.h"
#include "linklist.h"
#include "timer.h"

#define TCP_RETRIES1 3 // Amount of times we retry sending a packet before re-arping
#define TCP_RETRIES2 15 // Amount of times we retry sending before giving up
// TODO: this should be scaling 3->6->12->give up
#define TCP_ACK_TIMEOUT 3000 // Time in miliseconds before resending a packet

#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80

#define SYNACK 0x12

// TODO: refactor/add payload, cause won't work for recv/send() -> add packet linked list and send/recv buffers
struct tcp_session {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t daddr;
    int state;
    // TODO: do we need to store these here? Were storing them in the packets themselves too
    uint32_t seq_num;
    uint32_t ack_num;

    // next pointer
    struct tcp_session* next;
    struct tcp_session* prev;

    // Packet linked list pointer
    struct tcp_pkt* packets;
};

struct tcp_pkt {
    struct tcp_hdr* hdr;
    int retries;
    struct timer* timer;
    uint32_t daddr;
    void* buf;
    size_t size;

    struct tcp_pkt* next;
    struct tcp_pkt* prev;
};

// Add global struct array with tcp_session
extern struct tcp_session* TCP_SESSIONS;

static inline struct tcp_hdr *tcp_header(struct subuff *sub)
{
    return (struct tcp_hdr *)(sub->head + ETH_HDR_LEN + IP_HDR_LEN);
}

int tcp_tx(struct tcp_pkt* tcp_packet);

extern int send_tcp(struct tcp_pkt* tcp_packet, uint32_t dst_ip);

extern struct tcp_hdr* init_tcp_hdr();
extern struct tcp_pkt* init_tcp_packet();
extern void free_packet(struct tcp_pkt *tcp_packet);

extern struct tcp_session *get_tcp_session(uint16_t local_port, uint16_t remote_port, uint32_t daddr);

#define TCP_HDR_LEN sizeof(struct tcp_hdr)
#define TCP_SESSION_LEN sizeof(struct tcp_session)
#endif //ANPNETSTACK_TCP_H



#define TCP_DEBUG
#ifdef TCP_DEBUG
#define debug_TCP(str) \
    do { \
        printf("TCP_DEBUG %s\n", str);\
    } while(0)

#define debug_TCP_packet(str, hdr)                                               \
    do {                                                                \
        printf("TCP_PACKET %s (src_port: %hu, dst_port: %hu, seq_num: %hu, ack_num: %hu, flags: 0x%x, checksum: %.4hx)\n",         \
                    str, hdr->src_port, hdr->dst_port, hdr->seq_num, hdr->ack_num, hdr->flags, hdr->csum);                         \
    } while (0)

#endif // TCP_DEBUG

/* End segment */