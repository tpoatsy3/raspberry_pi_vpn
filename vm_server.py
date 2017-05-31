import sys, socket, select

from scapy.all import *

<<<<<<< HEAD
#
# VPN Server global variabes
#
VPN_IP = '192.168.56.101'
VPN_PORT = 18958
BUFFER_SZ = 1024

pkt_dict = {'10.5.0.100' : None, '10.5.0.2' : None}

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
def sendWaitingPkts( outer_pkt ) :
	print 'sendWaitingPkts not implemented'
	print 'Sending requested packets to %s ...' % outer_pkt[Raw].load
	return;


rSock = []
wSock = []
eSock = []
buf = []

#
# Initiate a UDP Host Socket
#
=======
rSock = []
wSock = []
eSock = []

buf = []

>>>>>>> 0cc0bd2af03cc876cf1030fe07fc3868d9754b75
server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
# server_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
<<<<<<< HEAD
server_socket.bind((VPN_IP, VPN_PORT))


=======


host = '192.168.1.9'
print host
port = 18958
server_socket.bind((host,port))

# rSock.append(server_socket)

>>>>>>> 0cc0bd2af03cc876cf1030fe07fc3868d9754b75


while True:
	print("**** in loop ****")
<<<<<<< HEAD
	response, addr = server_socket.recvfrom(BUFFER_SZ)
=======
	response, addr = server_socket.recvfrom(1000)
>>>>>>> 0cc0bd2af03cc876cf1030fe07fc3868d9754b75
	raw_pkt = IP(response)
	print "OUTER PACKET"
	raw_pkt.show()
	print
<<<<<<< HEAD
	

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


		innerUdp = UDP(response[48:56])
		destPort = innerUdp.dport
		piAddr = raw_pkt.dst
		sourceAddr = innerPkt.src
		targetAddr = innerPkt.dst

		print "IP ADDRESSES"
		print "Pi: ", piAddr
		print "Source: ", sourceAddr
		print "Target: ", targetAddr

		raw_pkt.dst = targetAddr
		raw_pkt.src = piAddr

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





=======
	print "INNER PACKET"

	innerPkt = IP(response[28:len(response)])
	innerPkt.show()
	print


	innerUdp = UDP(response[48:56])
	destPort = innerUdp.dport
	piAddr = raw_pkt.dst
	sourceAddr = innerPkt.src
	targetAddr = innerPkt.dst

	print "IP ADDRESSES"
	print "Pi: ", piAddr
	print "Source: ", sourceAddr
	print "Target: ", targetAddr

	raw_pkt.dst = targetAddr
	raw_pkt.src = piAddr

	outPkt = innerPkt
	outPkt.dst = targetAddr
	outPkt.src = piAddr

	del(outPkt.chksum)

	print
	print "OUT PACKET"
	outPkt.show2()

	n = server_socket.sendto(str(outPkt), (targetAddr, destPort))


server_socket.close()

>>>>>>> 0cc0bd2af03cc876cf1030fe07fc3868d9754b75
# "\x45\x00\x00\x54\x86\x73\x00\x00\x40\x01\xb4\x1a\x0a\x1f\x25\xed\x08\x08\x08\x08\x08\x00\xff\x62\xce\x17\x00\x01\x59\x2b\x7c\xf0\x00\x0e\x69\x57\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"

# InnerSource	-> Source
# InnerDest 	-> Target
# OuterSource	-> Pi
# OuterDest	-> Target

<<<<<<< HEAD
=======


>>>>>>> 0cc0bd2af03cc876cf1030fe07fc3868d9754b75
