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

#include "icmp.h"
#include "utilities.h"

void icmp_rx(struct subuff *sub)
{
    //FIXME: implement your ICMP packet processing implementation here
    //Hints:
    // Step 1: check if the incoming packet is a valid ICMP packet, does the checksum match?
    // Step 2: what kind of ICMP packet is this? See the
    // Step 3: take appropriate action for ECHO type request, i.e., prepare an ECHO response type (in the icmp_reply function below)
    // Step 4: make sure you do not leak any memory allocated to the sub
    free_sub(sub);
    assert(false);
}

void icmp_reply(struct subuff *sub)
{
    // FIXME: implement your ICMP reply implementation here
    // Hints:
    // Step 1: prepare an ICMP response buffer
    // Step 2: make sure that all fields are valid, in the network byte order, and the checksum is correct
    // Step 3: send it out on ip_ouput(...)
    // See how ARP processing is implemented for processing and sending packets
}
