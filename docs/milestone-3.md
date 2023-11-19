## Milestone summary: 
1. Setup and run the server-client example program with the Linux netstack. 
2. Make sure you can capture the packets and understand what is happening with tcpdump. 
3. Now run the client side code, with your ANP netstack. 
4. Implement socket, and connect calls in the libanp framework - make sure that the client side code can be run multiple times (not just once). 
5. Understand what you can implement and what is now allowed. Do not make network event ordering assumptions regarding which packet will arrive or send when. When in doubt, ask us. 
6. Prepare 1-2 slides (or just sketching on a piece of paper is also totally fine) to give an “graphical” visualization of the code you implement, mostly focusing on choice of data structure. 
7. Zip and the source code with the complete framework, and upload on Canvas within the deadline. 
8. Make sure you include everything with a running code. If we cannot compile your code, you will be graded as if you had a non-functioning incomplete code. You will not get an extension to fix your uploading mistakes. 
9. Prepare for the M3 interview and show up.

## Basically
We need to implement `connect()` and `socket`, all these need to do is to establish a TCP connection (undergo the 3 way handshake.)

The calls themselves (the api) is implemented in `anpwrapper.c`, the socket only needs to support selected calls, the rest can be passed on to the origional socket api.

Connect needs to do the following (curtesy of Philip)
```c
// Ok bois this is the briefing for the mission.
// We need to send a SYN packet to the destination.
// Then, we need to wait for a SYN-ACK packet from the destination.
// Then, we need to send an ACK packet to the destination.
// After that, we are connected to the destination. Yay!
// We most likely need to give up generally. Boo!
```

The wrapper should call `tcp.c`, which handles the three way handshake (I think)