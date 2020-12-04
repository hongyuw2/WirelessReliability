#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sniff, sendp, send, srp1, get_if_hwaddr
from scapy.all import Packet, hexdump
from scapy.all import Ether, IP, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
import readline

PAYLOAD_LENGTH = 1454
P4TCP_PROTOCOL = 0x09

class P4tcp(Packet):
    name = "P4tcp"
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x01),
                    StrFixedLenField("packetType", "D", length=1),
                    StrFixedLenField("srcPort", "0", length=2),
                    StrFixedLenField("dstPort", "0", length=2),
                    IntField("seqNo", 0),
                    IntField("ackNo", 0),
                    StrFixedLenField("dataPayload", "", length=PAYLOAD_LENGTH)]

bind_layers(IP, P4tcp, proto=P4TCP_PROTOCOL)

total_recv_packet = 0
latest_ack_no = 1
received_seqs = []

def main():
    iface = 'eth0'

    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x, iface))
        

def print_packet(tcp_pkt):
    print("Packet SEQ= %d, ACK=%d" % (tcp_pkt.seqNo, tcp_pkt.ackNo))

def determine_next_ack(seqs, curr_ack):
    ack = curr_ack
    found = False
    while (not found and len(seqs) > 0):
        ack = ack + PAYLOAD_LENGTH
        if (ack in seqs):
            seqs.remove(ack)
        else:
            found = True
    return ack

def handle_pkt(pkt, iface):
    global total_recv_packet, latest_ack_no
    if P4tcp in pkt:
        p4tcp = pkt[P4tcp]
        if (p4tcp.packetType == "D"):
            total_recv_packet = total_recv_packet + 1
            ackNo = 1
            seqNo = p4tcp.seqNo
            received_seqs.append(seqNo)
            if (latest_ack_no == seqNo): # common case
                ackNo = determine_next_ack(received_seqs, latest_ack_no)
                latest_ack_no = ackNo
            else:
                ackNo = latest_ack_no              
            tcp_pkt = P4tcp(dstPort=p4tcp.srcPort, srcPort=1234, packetType="A", seqNo=1, ackNo=ackNo) 
            print_packet(tcp_pkt)
            send_pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            send_pkt = send_pkt / IP(dst=pkt[IP].src, proto=P4TCP_PROTOCOL) / tcp_pkt
            sendp(send_pkt, iface=iface, verbose=False)
            # if (total_recv_packet % 100 == 0):
            #     print("Received packet = " + str(total_recv_packet))


if __name__ == '__main__':
    main()
