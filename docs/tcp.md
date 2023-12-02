## TCP
Relevant files:
- tcp.c/h
- anpwrapper.c/h -> API interface

## API interface
For TCP, we implement the following API interfaces, defined in anpwrapper.c/h:
#### socket
For this, we first check if the requested protocol is supported by us, this is just going to be
TCP over IPv4, this is done using `is_socket_supported`. 

If it is supported we allocate a new socket using `anp_fd_alloc`, update our `socket_array`, set the parameters and return the descriptor.

#### connect
Connect initiates a tcp connection, by taking a socket, setting its state (src & dst ip) and sends a
SYN packet. If the packet is ack'ed all is well, if not we time out and return `-1`.

#### send
In short, takes a socket, buffer, size and flags, sends the buffer.

For more information on the exact behavior: https://linux.die.net/man/3/send
#### recv
This does the reverse of send, it takes a buffer, socket and size and returns whatever has been
received. 

For this we need to have an internal buffer for each tcp session that contains all data received
and read from there.

For more information on the exact behavior: https://linux.die.net/man/2/recv

#### close
TODO: look into whats needed

## TCP interface
tcp.c we define the following two interfaces:
#### tcp_rx
This function is called from `ip_rx`, it takes a TCP packet and processes a response (if any). These responses are:
- SYN -> Return SYN-ACK
TODO: are there more? What are the CWR and ECE flags?

Currently the only response implemented is `SYN ACK`.

#### tcp_tx
This function takes a TCP header, ip address, and *should* take a payload. With this it constructs a TCP packet, allocates a new sub struct,
calculates the checksum and passes it on to `ip_output`.

Currently, if the ip address is `127.0.0.1` this will result in an infinite ARP loop. This is likely a bug.


#### TCP sessions
Tcp sessions are each individual connection, so each individual socket in this case. A session can be in
one of the following states:
- LISTEN 
- SYN-SENT 
- SYN-RECEIVED
- ESTABLISHED
- FIN-WAIT-1
- FIN-WAIT-2
- CLOSE-WAIT
- CLOSING
- LAST-ACK
- TIME-WAIT
- CLOSED

These are defined as the enum `tcp_states` in `tcp.h`

When we keep track of tcp connections we need to assign these states. The sessions are tracked using the local and remote ip/port's, see
https://stackoverflow.com/questions/11129212/tcp-can-two-different-sockets-share-a-port for more information.

Currently, only the headers are stored in the tcp session, so we need to extend it as follows:
1) Have a pool of all currently unacked tcp packets
2) Have a dynamic buffer for the received contents

We want to have a worker thread that enumerates all of these and resends them if the timeout is hit.

## TODO:
Explain the intended responses for different TCP packets
Explain how tcp flags work/are handled
Explain how we want to check for acks (and when we resend unacked packages)
Explain functions we still need to implement -> send/recv/close