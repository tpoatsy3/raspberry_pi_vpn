import sys, socket, select
from collections import deque

from scapy.all import *

#
# VPN Server global variabes
#
#VPN_IP = '192.168.56.101'
VPN_IP = '192.168.1.4'
VPN_PORT = 18958
BUFFER_SZ = 1024
CLIENT_RECEIVE_PORT = 6060

pkt_dict = {'10.5.0.100' : None, '10.5.0.101' : None}

#
# Function: Respond to Client Request for Packets
#
def isRequestPkt( outer_pkt ) :
	client_ip = outer_pkt[Raw].load
	print "checking if %s is in pkt_dict..." % client_ip
	if (client_ip in pkt_dict):
		return True
	else:
		return False;		

#
# Function: Send requested packets out of Dictionary
#
def sendWaitingPkts( request_pkt ) :
	b_snt = 0
	print 'Sending requested packets to %s ...' % request_pkt[Raw].load
	client_ip = request_pkt[Raw].load
	if (pkt_dict[client_ip] == None):
		return b_snt
	if ((len(pkt_dict[client_ip]) != 0)):
		buffered_pkt = pkt_dict[client_ip].pop()
		b_snt = server_socket.sendto(str(buffered_pkt), (request_pkt[IP].src, request_pkt[UDP].sport))
	print 'Sent %d bytes to client' % b_snt
	return b_snt;

#
# Function: When a Packet is received, add it to Dictionary
#
def addPktToDict( outer_pkt ) :
	return 0;





rSock = []
wSock = []
eSock = []
buf = []

#
# Initiate a UDP Host Socket
#
server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
# server_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
server_socket.bind((VPN_IP, VPN_PORT))




while True:
	print("**** in loop ****")
	response, addr = server_socket.recvfrom(BUFFER_SZ)
	raw_pkt = IP(response)
	print "OUTER PACKET"
	raw_pkt.show()
	print
	

	#
	# Is Packet a Request Pkt or Traffic Pkt
	#

	# Case: Request Packet
	if (isRequestPkt(raw_pkt)):
		sendWaitingPkts(raw_pkt)
		continue

	# Case: Regular Traffic Packet
	else:
		print "INNER PACKET"
		innerPkt = IP(response[28:len(response)])
		innerPkt.show()
		print

		inner_dst_ip = innerPkt[IP].dst
		if (inner_dst_ip in pkt_dict):
			print 'INNER PKT dest found in dictionary, adding to buffer'
			if (pkt_dict[inner_dst_ip] == None):
				pkt_dict[inner_dst_ip] = []
			pkt_dict[inner_dst_ip].insert(0, innerPkt)
		else:
			print "Did not recognize INNER PKT dest IP"
			

		#innerUdp = UDP(response[48:56])
		#destPort = innerUdp.dport
		#piAddr = raw_pkt.dst
		#sourceAddr = innerPkt.src
		#targetAddr = innerPkt.dst

		#print "IP ADDRESSES"
		#print "Pi: ", piAddr
		#print "Source: ", sourceAddr
		#print "Target: ", targetAddr

		#raw_pkt.dst = targetAddr
		#raw_pkt.src = piAddr

		#outPkt = innerPkt
		#outPkt.dst = targetAddr
		#outPkt.src = piAddr

		#del(outPkt.chksum)

		#print
		#print "OUT PACKET"
		#outPkt.show2()

		#n = server_socket.sendto(str(outPkt), (targetAddr, destPort))

#
# While Loop Ended
#

server_socket.close()





# "\x45\x00\x00\x54\x86\x73\x00\x00\x40\x01\xb4\x1a\x0a\x1f\x25\xed\x08\x08\x08\x08\x08\x00\xff\x62\xce\x17\x00\x01\x59\x2b\x7c\xf0\x00\x0e\x69\x57\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"

# InnerSource	-> Source
# InnerDest 	-> Target
# OuterSource	-> Pi
# OuterDest	-> Target

