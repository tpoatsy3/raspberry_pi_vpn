# VPN Gateway and Client

In this project we implement a elementary VPN Server and Clients in python (using Scapy module)

## How to run

We run this project using 3 separate machines. One with a routable IPv4 address.

### Rasbperry Pi VPN Server

1. This machine received our public IP as it is used for the VPN Server.
This was configured manually and placed on the Dartmouth Private Network.

2. To run the server, clone this repository and run the 'vm_server.py' script. 

```
$ sudo bash
# python vm_server.py
```

### VPN Clients

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
# ssh hacker@10.5.0.101
---- carries out standard SSH shell ---- 
```

## Testing

We carried out multiple tests on out VPN to include:

1. ping
2. ssh
3. scp of ~100KB file
i.e.
```
# scp <file> hacker@10.5.0.101:
``` 

## Project Architecture













