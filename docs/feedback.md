## Milestone 3
Good effort! Unfortunately, the solution does not seem to run to completion successfully (if we are mistaken, please let us know). The anp netstack fails to deliver the third (ACK) message of the handshake to the server. Thus it does not run to completion. 

1) anpwrapper.c:169 Hardcoded window size could have been a named constant for this milestone (especially if unsure of value). Think about retrieving this dynamically from the messages sent by the server to the client. 
2) tcp.h:73 Compiler warning about the struct subuff declaration. Please resolve such issues in the next milestone, as otherwise points will have to be deducted. 
3) tcp.h:90 Why not use the existing linked list implementation from the framework (see linklist.h). 
4) anpwrapper.c:174 Why not use a defined src port (in the ephemeral range)? 
5) tcp.c:86 Why not use the src port stored in your tcp session (currently the port is unitialized)? 
6) tcp.c:129 Usage of sub_reserve but no calls to sub_push (consider the state of the subbuff when calling ip_output). 
7) anpwrapper.c:166 Sequence number is set to 0. Should be a random value and should be stored in the tcp_session struct. You're encouraged to revisit the sequence and acknowledgement numbers and to think about why they should be stored for your connection. 
8) anpwrapper.c:196 A while loop is required here to wait for example on a conditional since the connect call should block until a connection is established. 
9) tcp.c:52 Client should not have to handle the case that a SYN message comes in. 
10) tcp.c:43 You need to take into account the current tcp session state when handling these messages. The behaviour changes based on what state the connection is in. 
11) tcp.c:162 Use timers to ensure transmission instead of using a while loop. 
12) tcp.c:160 Only handles retransmission if ip_output fails, what happens when a packet gets lost on the network (you never send that packet again after a certain time)? You should keep resending the SYN packet every x miliseconds so if it gets lost in the network your connect call can still connect. This should be done X number of times, after which the connect call times out and returns an error to the caller (make sure to clean up the state nicely). 
13) tcp.c:198 Should clean up the state nicely if you timeout. E.g., modify the tcp_session state to be closed (since you decide on a connection timeout). 


-2 late submission -2 no working code -1 no retransmission of lost packets (e.g., SYN packet) -0.5 no usage of src port (unitialized) 


#### Processing
1) We need to look into a way of dynamically allocating the window size
2) Done
3) Need to refactor to use linkedlist implementation -> do we? do we really? Its a bigger pain to work with.
4) Done
5) Done
6) Done
7) Need to define sequence number (why store ack numbers?)
8) Done?
9) Done
10) Done
11) Refactor using timers instead of while loops in tcp_tx
12) Improve error handling, retransmit if not ack'ed
13) Done

##### TODO:
1) refactor using linked list   -> Skipped
2) update linked list to include old packets
3) add timers