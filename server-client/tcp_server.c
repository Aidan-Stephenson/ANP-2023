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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>
#include "common.h"

static int show_help(){
    printf("Usage: anp_server -a ip_address -p port -c -h \n");
    printf("-a : a.b.c.d IPv4 address to bind the server to (default 0.0.0.0 (all))\n");
    printf("-p : port, as an integer (default, %d). \n", PORT);
    printf("-c : 1, 2, 3 which of the 3 configs (1=small, 2=medium, 3=large) to test, default is 1=small (4KB (default), 32KB, and 1MB). \n");
    printf("-h : shows help, and exits with success. No argument needed\n");
    return 0;
}

int run_test(int test_buffer_sz, struct sockaddr_in *server_addr)
{
    // debug
    char debug_buffer[INET_ADDRSTRLEN];
    int listen_fd, client_fd, len = 0, ret = -1, so_far = 0;
    int optval = 1;
    struct sockaddr_in client_addr;

    char *test_buffer = calloc (1, test_buffer_sz);
    if(NULL == test_buffer){
        printf("buffer allocation failed %d \n", -ENOMEM);
        return(-ENOMEM);
    }
    // create the listening socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if ( -1 == listen_fd) {
        printf("Error: listen socket failed, ret %d and errno %d \n", listen_fd, errno);
        return(-errno);
    }
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    printf("Socket successfully created, fd = %d \n", listen_fd);

    // bind the socket
    ret = bind(listen_fd, (struct sockaddr*)server_addr, sizeof(*server_addr));
    if (0 != ret) {
        printf("Error: socket bind failed, ret %d, errno %d \n", ret, errno);
        exit(-errno);
    }
    printf("Socket successfully bind'ed\n");
    // listen on the socket
    ret = listen(listen_fd, 1); // only 1 backlog
    if (0 != ret) {
        printf("Error: listen failed ret %d and errno %d \n", ret, errno);
        exit(-errno);
    }

    printf("Server listening.\n");
    len = sizeof(client_addr);
    client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &len);
    if ( 0 > client_fd) {
        printf("Error: accept failed ret %d errno %d \n", client_fd, errno);
        exit(-errno);
    }

    inet_ntop( AF_INET, &client_addr.sin_addr, debug_buffer, sizeof(debug_buffer));
    printf("new incoming connection from %s \n", debug_buffer);
    // first recv the buffer, then tx it back as it is
    so_far = 0;
    while (so_far < test_buffer_sz) {
        ret = recv(client_fd, test_buffer + so_far, test_buffer_sz - so_far, 0);
        if( 0 > ret){
            printf("Error: recv failed with ret %d and errno %d \n", ret, errno);
            return -ret;
        }
        so_far+=ret;
        printf("\t [receive loop] %d bytes, looping again, so_far %d target %d \n", ret, so_far, test_buffer_sz);
    }
    printf("OK: buffer received ok, pattern match : %s  \n", match_pattern(test_buffer, test_buffer_sz));
    // then tx it back as it is
    so_far = 0;
    while (so_far < test_buffer_sz){
        ret = send(client_fd, test_buffer + so_far, test_buffer_sz - so_far, 0);
        if( 0 > ret){
            printf("Error: send failed with ret %d and errno %d \n", ret, errno);
            return -ret;
        }
        so_far+=ret;
        printf("\t [send loop] %d bytes, looping again, so_far %d target %d \n", ret, so_far, test_buffer_sz);
    }
    printf("OK: buffer tx backed \n");

    // in order to initiate the connection close from the client side, we wait here indefinitely to receive more
    ret = recv(client_fd, test_buffer, test_buffer_sz, 0);
    printf("ret from the recv is %d errno %d \n", ret, errno);

    // close the two fds
    ret =close(client_fd);
    if(ret){
        printf("Error: client shutdown was not clean , ret %d errno %d \n ", ret, errno);
        return -ret;
    }
    ret = close(listen_fd);
    if(ret){
        printf("Error: server listen shutdown was not clean , ret %d errno %d \n ", ret, errno);
        return -ret;
    }
    printf("OK: server and client sockets closed\n");
    free(test_buffer);
    return 0;
}

int main(int argc, char** argv){
    char c;
    int config = 1;
    int port = PORT, ret;
    // debug
    char debug_buffer[INET_ADDRSTRLEN];
    // set the default values
    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    while ((c = getopt(argc, argv, "a:p:c:h")) != -1) {
        switch (c) {
            case 'h':
                show_help();
                exit(0);
            case 'c':
                config = strtol(optarg, NULL, 0);
                break;
            case 'a':
                // it overwrites the port value, so must be reset the port value
                ret = get_addr(optarg, (struct sockaddr*) &server_addr);
                if (ret) {
                    printf("Invalid IP %s \n", optarg);
                    return ret;
                }
                server_addr.sin_port = htons(port);
                break;
            case 'p':
                port = strtol(optarg, NULL, 0);
                // does not touch the IP address, so ok
                server_addr.sin_port = htons(port);
                break;
            default:
                show_help();
                exit(-1);
        }
    }
    inet_ntop( AF_INET, &server_addr.sin_addr, debug_buffer, sizeof(debug_buffer));
    printf("[server] working with the following IP: %s and port %d (config: %d) \n", debug_buffer, ntohs(server_addr.sin_port), config);
    switch (config) {
        case 1:
            ret = run_test(SMALL_BUF, &server_addr);
            assert(ret == 0);
            break;
        case 2:
            ret = run_test(MEDIUM_BUF, &server_addr);
            assert(ret == 0);
            break;
        case 3:
            ret = run_test(LARGE_BUF, &server_addr);
            assert(ret == 0);
            break;
        default:
            printf("Wrong config number %d \n", config);
            show_help();
            exit(-1);
    }
    return ret;
}