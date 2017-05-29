import pytun
from scapy.all import *
import socket
import select

RECV_BUF_SZ = 65000

def main():	
	tun = pytun.TunTapDevice(name='tun0', flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
	tun.addr = '10.5.0.1'
	tun.dstaddr = '10.5.0.2'
	tun.netmask = '255.255.255.0'
	tun.mtu = 1500
	tun.up()

	#subprocess.check_call("ifconfig %s 10.5.0.1 up" % ifname, shell=True)              
	#subprocess.check_call("route add -net 10.5.0.0 netmask 255.255.255.0 dev %s" % ifname, shell=True)

	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	sock.bind(('192.168.56.100', 6666))		 # local addr and port
	
	remote_addr = '192.168.56.1'
	remote_port = 8888

	read = [tun, sock];
	write = [];
	execute = []; # should not be used??? 

	# create a test ping packet to be sent on start-up
	pkt = IP(dst="8.8.8.8", src="10.0.0.100")/ICMP()
	del pkt[IP].chksum
	pkt.show2()

	to_tun = str(pkt)
	to_sock = ''
	temp_buf = ''


	tun.write(to_tun)
	while True:

		try:
			read, write, execute = select.select(read, write, execute)		
			
			# read from TUN
			if tun in read:
				print 'about to tun.read'
				to_sock = tun.read(tun.mtu)
				print 'just read from TUN to to_sock:'
				print ":".join("{:02x}".format(ord(c)) for c in to_sock); 
			#read from socket
			if sock in read:
				temp_buf, recv_addr = sock.recvfrom(RECV_BUF_SZ)
				rcvd_pkt = IP(temp_buf)
				if (rcvd_pkt[TCP].dport == 6666):
					rcvd_pkt.show()
				else:
					to_tun = ''
			# write to TUN
			if tun in write:
				print 'about to write to TUN:'
#				print ":".join("{:02x}".format(ord(c)) for c in to_tun); 
				tun.write(to_tun)
				to_tun = ''
			# write to socket			
			if sock in write:
				print 'about to write to socket:'
				print ":".join("{:02x}".format(ord(c)) for c in to_sock); 
				sock.sendto(to_sock, (remote_addr, remote_port))
				to_sock = ''
			
			read = []
			write = []
			
			if to_tun:
				write.append(tun)
			else:
				read.append(sock)
			if to_sock:
				write.append(sock)
			else:
				read.append(tun)
			
		except Exception as e:
			print 'exception in while loop:'
			print e
			break
	
	return 0

if __name__ == '__main__':
	main()
	exit()
