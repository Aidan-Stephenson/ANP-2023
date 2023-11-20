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

//XXX: _GNU_SOURCE must be defined before including dlfcn to get RTLD_NEXT symbols
#define _GNU_SOURCE

#include <dlfcn.h>
#include "systems_headers.h"
#include "linklist.h"
#include "anpwrapper.h"
#include "init.h"
#include "tcp.h"
#include "ethernet.h"
#include "utilities.h"
#include "subuff.h"
#include "timer.h"


static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;
static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int sockfd) = NULL;

// Keep track of the file descriptors that we have allocated
static bool fd_array[MAX_FILE_DESCRIPTORS] = {false};
static struct anp_socket_t *socket_array[MAX_FILE_DESCRIPTORS] = {NULL};
// Initialise TCP_SESSIONS to NULL by accessing the one in tcp.h
struct tcp_ses *TCP_SESSIONS = NULL;

int anp_fd_alloc(){
    for(int i = 0; i < MAX_FILE_DESCRIPTORS; i++){
        if(fd_array[i] == false){
            fd_array[i] = true;
            // Allocate a new socket
            struct anp_socket_t *new_socket = (struct anp_socket_t *) malloc(sizeof(struct anp_socket_t));
            new_socket->fd = GET_ANP_FD(i);
            new_socket->state = SOCKET_STATE_UNCONNECTED;
            socket_array[i] = new_socket;
            return GET_ANP_FD(i);
        }
    }
    return -1;
}

int anp_fd_free(int fd){
    fd = GET_REAL_FD(fd);
    if(fd < 0 || fd >= MAX_FILE_DESCRIPTORS){
        return -1;
    }
    free(socket_array[fd]); // bye bye socket
    fd_array[fd] = false;
    return 0;
}

// Function to check if the file descriptor is allocated by the anpnetstack
static bool is_anp_sockfd(int fd){
    fd = GET_REAL_FD(fd);
    if(fd < 0 || fd >= MAX_FILE_DESCRIPTORS){
        return false;
    }
    return fd_array[fd];
}

static int is_socket_supported(int domain, int type, int protocol)
{
    // we are only going to handle TCP STREAM sockets on the IPv4
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM)) {
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        return 0;
    }
    printf("supported socket domain %d type %d and protocol %d \n", domain, type, protocol);
    return 1;
}



/**
 * @brief Wrapper function for the socket system call.
 *
 * This function checks if the specified socket parameters are supported by the anpnetstack.
 *
 * @param domain The domain of the socket (AF_INET, AF_INET6, etc.).
 * @param type The type of the socket (STREAM, DGRAM, RAW, etc.).
 * @param protocol The protocol of the socket (IPPROTO_TCP, IPPROTO_UDP, etc.).
 * 
 * Note: we handle TCP STREAM sockets on the IPv4 only.
 * 
 * @return The file descriptor of the created socket, or -1 if an error occurred.
 */
int socket(int domain, int type, int protocol) {
    int ret = 0;
    if (is_socket_supported(domain, type, protocol)) {
        // Lets start by allocating a file descriptor
        int fd = anp_fd_alloc();
        if(fd < 0){
            return -EMFILE;
        }
        // Initialize the socket
        struct anp_socket_t *new_socket = socket_array[GET_REAL_FD(fd)];
        new_socket->domain = domain;
        new_socket->type = type;
        new_socket->protocol = protocol;
        return fd;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    return _socket(domain, type, protocol);
}

/**
 * @brief Wrapper function for the connect system call.
 *
 *  The connect() system call connects the socket referred to by the
    file descriptor sockfd to the address specified by addr.  The
    addrlen argument specifies the size of addr.  The format of the
    address in addr is determined by the address space of the socket
    sockfd; see socket(2) for further details.
 *
 * @param sockfd The file descriptor of the socket.
 * @param addr The address structure of the destination.
 * @param addrlen The length of the address structure.
 * 
 * @return 0 if the connection was successful, or -1 if an error occurred.
 */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret = 0;
    if(is_anp_sockfd(sockfd)){
        // Fill in the destination IP address and port number
        struct sockaddr_in *dest_addr = (struct sockaddr_in *) addr;
        struct anp_socket_t *socket = socket_array[GET_REAL_FD(sockfd)];
        socket->dst_ip = dest_addr->sin_addr.s_addr;
        socket->dst_port = dest_addr->sin_port;

        // Print the connection details
        printf("[%d] Connecting to %s:%d\n",sockfd, inet_ntoa(dest_addr->sin_addr), ntohs(dest_addr->sin_port));

        // Main thing left to do here is to find a way to allocate a local port and to busy wait, and a whole bunch of debugging probably.

        // Send sync
        struct tcp_hdr *syc_packet = malloc(sizeof(struct tcp_hdr));
        // syc_packet->src_port = htons(src_port); // TODO: allocate port
        syc_packet->dst_port = socket->dst_port;
        syc_packet->seq_num = htonl(0); //TODO: this cant be 0 all the time because we need to assume multiple connections
        syc_packet->ack_num = htonl(0);  //TODO: same as above
        syc_packet->flags = SYN;
        syc_packet->window_size = htons(1600); // Honestly don't know  //LUKA: SYN packet has no payload, so window size is put as 1, referred to as a ghost Byte 
        syc_packet->urgent_ptr = htons(0); // We don't use it
        debug_TCP("connect:", syc_packet);
        struct tcp_ses* tcp_ses = malloc(sizeof(tcp_ses));
        // tcp_ses->src_port // TODO: allocate port
        tcp_ses->dst_port = socket->dst_port;
        tcp_ses->daddr = dest_addr->sin_addr.s_addr; 
        tcp_ses->state = TCP_SYN_SENT;
        if (TCP_SESSIONS == NULL)
        {
            TCP_SESSIONS = tcp_ses;
            printf("TCP_SESSIONS is NO LONGER NULL\n");
        }
        else
        {
            tcp_ses->next = TCP_SESSIONS;
            TCP_SESSIONS = tcp_ses;
        }

        // TODO: register session, see tcp.h for details, not fully implemented

        int res = send_tcp(syc_packet, socket->dst_ip);
        // Poll using the timer.c functions to see if we have received a SYNACK
        //DONT USE WHILE LOOP PROFESSOR DOESNT LIKE IT
        int starting_time = timer_get_tick(); //gets the current tick from the timers thread thats started by default start up
        int timeout = 10000; // 10 second timeout
        while(tcp_ses->state != TCP_ESTABLISHED){
            if(timer_get_tick() - starting_time > timeout){
                printf("Connection timed out\n");
                return -1;
            }
            else
            {
                /* check if SYN_ACK packet recieved */
            }
            
        }

        // Print the connection status
        if (ret == 0) {
            printf("Connection successful\n");
        } else {
            printf("Connection failed\n");
        }
        return ret;
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    int ret = -ENOSYS;
    if(is_anp_sockfd(sockfd)) {
        //TODO: implement your logic here
        assert(ret == 0);
        return ret;
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    int ret = -ENOSYS;
    if(is_anp_sockfd(sockfd)) {
        //TODO: implement your logic here
        assert(ret == 0);
        return ret;
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    if(is_anp_sockfd(sockfd)) {
        anp_fd_free(sockfd);
        return 0;
    }
    // the default path
    return _close(sockfd);
}

void _function_override_init()
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
}

