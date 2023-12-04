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
#ifndef ANPNETSTACK_ANPWRAPPER_H
#define ANPNETSTACK_ANPWRAPPER_H

#define MAX_FILE_DESCRIPTORS 1024
#define FILE_DESCRIPTOR_OFFSET 1000000 // Instructed by the assignment

#define GET_REAL_FD(fd) (fd - FILE_DESCRIPTOR_OFFSET)
#define GET_ANP_FD(fd) (fd + FILE_DESCRIPTOR_OFFSET)

#define SOCKET_STATE_UNCONNECTED 0
#define SOCKET_STATE_CONNECTED 1
#define SOCKET_STATE_FUCKED -1

struct anp_socket_t {
    int fd;
    int domain;
    int type;
    int protocol;
    int state;
    uint32_t dst_ip;
    uint16_t dst_port;
    struct tcp_session* tcp_session;
};

void _function_override_init();

#endif //ANPNETSTACK_ANPWRAPPER_H
