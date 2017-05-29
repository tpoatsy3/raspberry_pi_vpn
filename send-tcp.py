#!/usr/bin/env python

#
#  send a series of TCP segments one after another, ack-ing whatever the server sends
#

#    S ->
#      <- S+A
#    A ->

#  This needs to block outgoing RSTs to target so that the kernel doesn't spoil our game
#    iptables -A OUTPUT -p tcp -d <target> --dport <port> --tcp-flags RST RST -j DROP
#                                                                 mask^^^ ^^^value

segments = ["GET /awe", "some/\r\n\r\n" ]
segments.reverse() # so we could use pop

from scapy.all import *
import sys
import random

payload = 'Testing123'

dst = '192.168.56.1'

def ack_and_send(pkt):
    # First, need to filter out spurious packets: tcpdump filter seems to fail---or maybe
    #  only kicks in after a few packets.
    global dst
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].src == dst and
            pkt[TCP].sport == 80 ):
        print "SPURIOUS: ", pkt.summary()
        return

    if pkt.haslayer(TCP) and pkt[TCP].flags & 0x10 : # ACK set
        print pkt.summary()

        # let's see what we got
        global payload
        if pkt.haslayer(Raw) :
            payload += pkt[Raw].load

        # prepare a response packet
        i = pkt[IP].copy()
        i.remove_payload()

        i.dst, i.src = i.src, i.dst
        i.chksum  = None
        i.len    = None

        t = pkt[TCP].copy()
        t.remove_payload()

        t.flags = 0x10    # we want to suppress SYN when set
        t.sport, t.dport = t.dport, t.sport
        t.ack, t.seq     = t.seq, t.ack

        if pkt[TCP].flags & 0x2 : # this is a SYN/ACK
            t.ack = t.ack + 1
        else:                     # otherwise we have some payload bytes to acknowledge
            t.ack = t.ack + (len(pkt[Raw].load) if pkt.haslayer(Raw) else 0)
        t.chksum = None

        # be nice and send a FIN packet when we see FIN
        if pkt[TCP].flags & 0x1 :
            t.flags |= 0x1

        load = Raw(load = "")
        if len(segments) > 0 :
            load = Raw(load = segments.pop())

        p = i/t/load

        # p.show()

        send(p)

        if t.flags & 0x1 : # and exit after we sent FIN
            print payload
            sys.exit()

    elif pkt.haslayer(TCP) and pkt[TCP].flags & 0x4 : # RST, we screwed up
        print "RST: " + pkt.summary()
        print "Sorry"
        sys.exit()
    else:
        print "SKIP: " + pkt.summary()

send( IP(dst=dst )/TCP( dport=80, sport=random.randint(10000, 20000), flags = 0x02) )    # send SYN
sniff( filter="( ip src "+ dst + " ) and ( tcp src port 80 )", prn=ack_and_send )
