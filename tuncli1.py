#!/usr/bin/env python
from scapy.all import *

import os
import subprocess
import socket

import pytap    # my pytab wrapper around basic system-specific syscalls

#
# Global variables
#
VPN_IP = '129.170.237.60'
VPN_PORT = 18958
CLIENT_IP = '10.5.0.100'
CLIENT_PORT = 6666
CLIENT_REQUEST_PORT = 6060
CLIENT_OUTER_IP = '192.168.56.100'
CLIENT_OUTER_PORT = 2003

#
# Allocating tun0 interface
#
tun, ifname = pytap.open('tun0')
print "Allocated interface %s. Configuring it." % ifname

subprocess.check_call("ifconfig %s 10.5.0.100 up" % ifname, shell=True)
subprocess.check_call("ifconfig %s mtu 1000" % ifname, shell=True)
subprocess.check_call("ifconfig eth0 mtu 1000", shell=True)
subprocess.check_call("route add -net 10.5.0.0 netmask 255.255.255.0 dev %s" % ifname, shell=True)

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sock.bind((CLIENT_OUTER_IP, CLIENT_OUTER_PORT))

sock2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sock2.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sock2.settimeout(0.1)
sock2.bind((CLIENT_OUTER_IP, CLIENT_REQUEST_PORT))

#
#  Now process packets
#
while 1:
	# get packet routed to our "network"
    binary_packet = ''

    try:
        binary_packet = os.read(tun, 2048)
        if binary_packet == '' :
    		print 'os.read read 0 bytes'

    	# The packet may be IPv4 or IPv6.
        # Parsing IPv6 as IPv4 will give strange results, so check which we got.
        if ord(binary_packet[0]) == 0x60 :
            packet = IPv6(binary_packet)  # Scapy parses byte string into a packet object
        else:
            packet = IP(binary_packet)

        # Send packet to VPN server over socket  using write() with encapsulation
        packet_wrapped = IP(src=CLIENT_OUTER_IP, dst=VPN_IP)/UDP(sport=CLIENT_OUTER_PORT, dport=VPN_PORT)/packet

        del packet_wrapped[IP].chksum
        packet_wrapped = packet_wrapped.__class__(str(packet_wrapped))


        packet_wrapped.show()
        sock.sendto(str(packet_wrapped),(VPN_IP, VPN_PORT))
    except:
		binary_packet = ''


    # tell VPN server that I am 10.5.0.100 so it gives me all the packets for that addresses
    # include IP in pull request to server. Have to write that protocol.
    rec_request_pkt = IP(src=CLIENT_OUTER_IP, dst=VPN_IP)/UDP(sport=CLIENT_REQUEST_PORT,dport=VPN_PORT)/Raw(CLIENT_IP)
    sock2.sendto(str(rec_request_pkt),(VPN_IP, VPN_PORT))

    buff = ''
    try:
        buff, address = sock2.recvfrom(1500)
        print "sock2.recvfrom received:"
        #print buff
        # Strip the outer header off
        inner_pkt = buff[28:]
        IP(inner_pkt).show2()
        os.write(tun, inner_pkt)
    except:
        continue


    # print packet.summary()
    # print hexdump(packet)


    # Server:
    # dictionary/hashtable of received packets
