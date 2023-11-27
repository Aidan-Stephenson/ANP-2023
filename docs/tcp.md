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
- SYN -> Return SYN-ACK
TODO: are there more? What are the CWR and ECE flags?

Currently the only response implemented is `SYN ACK` (but this is currently buggy).

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

When we keep track of tcp connections we need to assign these states.


## TODO:
Explain the intended responses for different TCP packets
Explain how tcp flags work/are handled
Explain connect
Explain how we want to check for acks (and when we resend unacked packages)
Explain functions we still need to implement -> send/recv/close

## Known bugs
#### tcp_tx double send
Currently, when tcp_rx (or tcp_send is called twice), the packet is malformed.
Example packet:
```
0000   3a 34 9a 3c 3d 26 de ad be ef aa aa 08 00 e0 04
0010   cb a8 00 00 00 00 00 00 00 00 5e 10 06 40 db 70
0020   00 00
```

Valid (preceding) packet:
```
0000   3a 34 9a 3c 3d 26 de ad be ef aa aa 08 00 45 00
0010   00 28 00 00 40 00 40 06 26 5a 0a 00 00 04 0a 6e
0020   00 05 00 00 a8 cb 00 00 00 00 00 00 00 00 50 02
0030   06 40 ec 60 00 00
```

Debug log:
### First call
subbuff
```
$1 = {
  list = {
    next = 0x55be4d1dd1b0,
    prev = 0x55be4d1dd1b0
  },
  rt = 0x0,
  dev = 0x0,
  protocol = 0x6,
  seq = 0x0,
  end_seq = 0x0,
  head = 0x55be4d1dd220 "",
  end = 0x55be4d1dd256 "",
  data = 0x55be4d1dd256 "",
  len = 0x0,
  payload = 0x0,
  dlen = 0x0
}
```

Origional header
```
$2 = {
  src_port = 0x0,
  dst_port = 0xcba8,
  seq_num = 0x0,
  ack_num = 0x0,
  reserved = 0x0,
  data_offset = 0x5,
  flags = 0x2,
  window_size = 0x4006,
  csum = 0x0,
  urgent_ptr = 0x0
}
```

Header copy
```
$3 = {
  src_port = 0x0,
  dst_port = 0xcba8,
  seq_num = 0x0,
  ack_num = 0x0,
  reserved = 0x0,
  data_offset = 0x5,
  flags = 0x2,
  window_size = 0x4006,
  csum = 0x60ec,
  urgent_ptr = 0x0
}
```

### Second call
subbuff
```
$4 = {
  list = {
    next = 0x55be4d1dd310,
    prev = 0x55be4d1dd310
  },
  rt = 0x0,
  dev = 0x0,
  protocol = 0x6,
  seq = 0x0,
  end_seq = 0x0,
  head = 0x55be4d1dd380 "",
  end = 0x55be4d1dd3b6 "",
  data = 0x55be4d1dd3b6 "",
  len = 0x0,
  payload = 0x0,
  dlen = 0x0
}
```

Origional header
```
$5 = {
  src_port = 0xd1dd,
  dst_port = 0xcba8,
  seq_num = 0x0,
  ack_num = 0x0,
  reserved = 0x0,
  data_offset = 0x5,
  flags = 0x2,
  window_size = 0x4006,
  csum = 0x0,
  urgent_ptr = 0x0
}
```

Header copy
```
$6 = {
  src_port = 0xd1dd,
  dst_port = 0xcba8,
  seq_num = 0x0,
  ack_num = 0x0,
  reserved = 0x0,
  data_offset = 0x5,
  flags = 0x2,
  window_size = 0x4006,
  csum = 0x8f0e,
  urgent_ptr = 0x0
}
```

Debug:
    printf("Calling IP_output with @ p *(struct subuff *) %p\n", sub);
    printf("Origional TCP packet @ p *(struct tcp_hdr *) %p\n", tcp_hdr_origional);
    printf("Copy of TCP packet @ p *(struct tcp_hdr *) %p\n", tcp_hdr_sub);