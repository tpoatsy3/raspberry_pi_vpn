#!/usr/bin/env python

#
#  Fake ICMP and ARP responses from non-existings IPs via tap0.
#   Create fake MAC addresses on the fly.
#

from scapy.all import *

import os
import subprocess
import socket

import pytap    # my pytab wrapper around basic system-specific syscalls

tun, ifname = pytap.open('tun0')
print "Allocated interface %s. Configuring it." % ifname

subprocess.check_call("ifconfig %s 10.5.0.100 up" % ifname, shell=True)
subprocess.check_call("route add -net 10.5.0.0 netmask 255.255.255.0 dev %s" % ifname, shell=True)

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sock.connect(('129.170.239.178', 18958))

sock2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sock2.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sock2.settimeout(.1)
sock2.connect(('129.170.239.178', 18959))




#  Now process packets
while 1:

    binary_packet = os.read(tun, 2048)   # get packet routed to our "network"

    # The packet may be IPv4 or IPv6.
    #   Parsing IPv6 as IPv4 will give strange results, so check which we got.
    if ord(binary_packet[0]) == 0x60 :
        packet = IPv6(binary_packet)  # Scapy parses byte string into a packet object
    else:
        packet = IP(binary_packet)




    # Send packet to VPN server over socket  using write() with encapsulation
    packet_wrapped = IP(src='192.168.56.100', dst='129.170.239.178')/UDP(sport=2003, dport=18958)/packet

    # packet_wrapped.version  = "4L"
    # packet_wrapped.ihl = "5L"
    del packet_wrapped[IP].chksum
    packet_wrapped = packet_wrapped.__class__(str(packet_wrapped))


    # packet_wrapped.show()
    sock.sendto(str(packet_wrapped),('129.170.239.178', 18958))


    # tell VPN server that I am 10.5.0.100 so it gives me all the packets for that addresses
    # include IP in pull request to server. Have to write that protocol.
    rec_request_pkt = IP(src="192.168.56.100", dst="129.170.239.178")/UDP(sport=6060,dport=18959)/Raw("10.5.0.100")
    sock2.sendto(str(rec_request_pkt),('129.170.239.178', 18959))

    buff = ''
    try:
        buff, address = sock2.recvfrom(65000)
        # Strip the outer header off
    except:
        continue

    os.write(tun, buff)

    # print packet.summary()
    # print hexdump(packet)


    # Server:
    # dictionary/hashtable of received packets
