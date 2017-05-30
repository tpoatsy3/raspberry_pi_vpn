import sys, socket, select

from scapy.all import *

rSock = []
wSock = []
eSock = []

buf = []

server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
# server_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


host = '192.168.1.9'
print host
port = 18958
server_socket.bind((host,port))

# rSock.append(server_socket)



while True:
	print("**** in loop ****")
	response, addr = server_socket.recvfrom(1000)
	raw_pkt = IP(response)
	print "OUTER PACKET"
	raw_pkt.show()
	print
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

# "\x45\x00\x00\x54\x86\x73\x00\x00\x40\x01\xb4\x1a\x0a\x1f\x25\xed\x08\x08\x08\x08\x08\x00\xff\x62\xce\x17\x00\x01\x59\x2b\x7c\xf0\x00\x0e\x69\x57\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"

# InnerSource	-> Source
# InnerDest 	-> Target
# OuterSource	-> Pi
# OuterDest	-> Target



