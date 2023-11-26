## TCP
Relevant files:
- tcp.c/h
- anpwrapper.c/h -> API interface

## API interface
For TCP, we implement the following API interfaces, defined in anpwrapper.c/h:
#### socket
For this, we first check if the requested protocol is supported by us, this is just going to be
TCP over IPv4, this is done using `is_socket_supported`. 

If it is supported we allocate a new socket using `anp_fd_alloc`, update our `socket_array`, set the parameters
and return the descriptor.

#### connect
TODO -> Luka?

#### send
TODO

#### recv
TODO

#### close
TODO

## TCP interface
tcp.c we define the following two interfaces:
#### tcp_rx
This function is called from `ip_rx`, it takes a TCP packet and processes a response (if any). These responses are:
TODO

Currently the only response implemented is `SYN ACK` (but this is currently buggy).

#### tcp_tx
This function takes a TCP header, ip address, and *should* take a payload. With this it constructs a TCP packet, allocates a new sub struct,
calculates the checksum and passes it on to `ip_output`.

Currently, if the ip address is `127.0.0.1` this will result in an infinite ARP loop. This is likely a bug.


## TODO:
Explain tcp sessions
Explain the intended responses for different TCP packets
Explain how tcp flags work/are handled
Explain connect
Explain how we want to check for acks (and when we resend unacked packages)
Explain functions we still need to implement -> send/recv/close