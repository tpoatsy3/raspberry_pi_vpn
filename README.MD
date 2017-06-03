# Virtual Private Network Project
 
**Contributors:** Rob Sayegh, John Graham, Ted Poatsy
 
## Description
 
This project creates a Virtual Private Network with a Raspberry Pi. The private network is between all of the computers that both know the IP address and port of the Raspberry Pi and can run a client program. 
 
## Functionality
 
The VPN allows for the following functionality:
  * Ping
  * Secure Copy
  * Secure Shell
 
 
## Components
 
##### Hardware:
  * Two computers that can run a script
  * A Raspberry Pi
  * Internet connection
 
##### Software:
  * `tuncli1.py`
  * `tuncli2.py`
  * `pytap.py`
  * `vm_server`
 
***Note:*** `tuncli1.py` and `tuncli2.py` are identical in terms of their code except for the VPN IP address that they request from the server. The VPN can be scaled to support a reasonable number of clients with the same piece of software. 
 
 
## Configuration
 
##### Server:
 
  1. Start up your Raspberry Pi.
  2. Connect your Pi to the internet.
  3. Secure Copy `vm_server.py` onto the Pi.
  4. Open a terminal
  5. `cd` into the directory holding `vm_server.py`
  6. Run `python vm_server.py`
 
##### Client:
 
  // Steps: 
    * Create tun interface
    * Set-up the MTU's correctly
    * Run the software
 
1. tuncli1.py must be run on a machine with a default interface IPv4 address '192.168.56.100' and will receive a VPN address of '10.5.0.100'

2. tuncli.py must be run on a machine with a default interface IPv4 address '192.168.56.101' and will receive a VPN Address of '10.5.0.101'

The following is an example of configuring and running one of the clients. It assumes the otehr client is already up and running.

```
$ sudo bash
# ifconfig tun0 mtu 1400 up
# python tuncli1.py
```

In another terminal:

```
# ping 10.5.0.101
---- observe for reply pings ----
^C
```
 
## Testing
 
After configuration, test the VPN by using the following commands:
 
##### Ping:
  * From client 1, run `ping 10.5.0.100`
  * From client 2, run `ping 10.5.0.101`
 
##### scp:
1. Pick a file to be copied on Client 1
2. Run `scp <file> <username>@10.5.0.101`
3. When prompted enter the password for client 2's machine
4. To confirm, run `md5sum` on the file on the source and target machine and compare.
 
##### ssh:
  * From client 1, run `ssh <Client 2's username>@10.5.0.101`
  * From client 2, run `ssh <Client 1's username>@10.5.0.100`
 
## Outside Resources Used
 
In our code, we used `pytun.py` from `montag451`'s GitHub repository. We also used Scapy for packet manipulation and interpretation. Lastly, we considered the code and information kept at `cs.dartmouth.edu/~sergey/netreads/`. 
 
## Design
 
Our VPN works in the following way. We set up the virtual interface, `tun` on all client computers. Packets that are sent over the VPN are sent through the virtual interface, `tun`. We wrap all packets that go through `tun` with an outer IP header that will route the packets to the VPN's server (in this case a Raspberry Pi). The packets are then sent to server through the client's default interface.
 
The server then receives the packets and unwraps the outer header. If the destination IP is among the IP's that the server recognizes, then it will store the inner packet in a buffer for the destination IP. 
 
Meanwhile, the clients are constantly sending packets to the server requesting that the server forward whatever packets the server has for it with simple "request" packet. When the server gets one of these requests, it empties the list of packets in the correct order and sends them to the client.
 
The client receives whatever packets the server sends to it, unwraps the packets, and interprets them through the kernel. 
 
