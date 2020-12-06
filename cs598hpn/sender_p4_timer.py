#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re
import string
import threading
import time

from Queue import PriorityQueue

from scapy.all import sniff, sendp, send, srp1, get_if_hwaddr
from scapy.all import Packet, hexdump
from scapy.all import Ether, IP, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
import readline

PAYLOAD_LENGTH = 1454
P4TCP_PROTOCOL = 0x09
RTO = 0.5

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

def randStr(chars = string.ascii_uppercase + string.digits, N=10):
    return ''.join(random.choice(chars) for _ in range(N))

MAX_CWND = 300
NUM_PACKETS_TO_SEND =  500

# SHARED VAR
cwnd = 4
ssthresh = 300
currently_sent = 0
count_sent_packets = 0
lock = threading.Lock()
lastAckNo = 0
dup_ack_counter = 0
sent_packets = []

def print_packet_receive(tcp_pkt):
    print("Received packet SEQ= %d, ACK=%d" % (tcp_pkt.seqNo, tcp_pkt.ackNo))

def print_packet_send(tcp_pkt):
    print("Sent packet SEQ= %d, ACK=%d" % (tcp_pkt.seqNo, tcp_pkt.ackNo))

def send_packet(seq_no, iface, addr):
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    message = randStr(N=10)
    tcp_pkt = P4tcp(dstPort=1234, srcPort=2345, seqNo=seq_no, ackNo=1, dataPayload=message)
    pkt = pkt / IP(dst=addr, proto=P4TCP_PROTOCOL) / tcp_pkt
    sendp(pkt, iface=iface, verbose=False)
    return tcp_pkt

# Sending data
def send_thread(addr, iface):
    global cwnd, currently_sent, lock, sent_packets
    curr_seq_no = 1
    count_sent_packets = 0
    start_time = time.time()

    while True:
        if (currently_sent < cwnd):
            tcp_pkt = send_packet(curr_seq_no, iface, addr)
            curr_seq_no = curr_seq_no + PAYLOAD_LENGTH
            count_sent_packets = count_sent_packets + 1
            # print("Sent packets = " + str(count_sent_packets))
            if (count_sent_packets >= NUM_PACKETS_TO_SEND):
                break
            lock.acquire()
            currently_sent = currently_sent + 1
            lock.release()

    end_time = time.time()
    elapsed_time = end_time - start_time
    print("Flow completion time: %f s, total packets : %d" % (elapsed_time, count_sent_packets))

def delete_sent_packets(sent_packets, ack_num):
    for seq in sent_packets:
        if (seq < ack_num):
            sent_packets.remove(seq)

# Getting ack packet, and set cwnd
def ack_thread(addr, iface):

    def handle_ack(pkt, addr, iface):
        global cwnd, ssthresh, currently_sent, lastAckNo, dup_ack_counter, sent_packets
        if P4tcp in pkt:
            p4tcp = pkt[P4tcp]
            if (p4tcp.packetType == "A"): # ACK packet
                # print_packet_receive(p4tcp)
                ackNum = p4tcp.ackNo
                if (ackNum > lastAckNo):
                    lastAckNo = ackNum
                    if (cwnd <= ssthresh): # Slow start phase
                        cwnd = min(cwnd * 2, MAX_CWND)
                    else: # Congestion avoidance phase
                        cwnd = min(cwnd + 1, MAX_CWND)
                    print("Cwnd: " + str(cwnd))
                    dup_ack_counter = 0
                    # lock.acquire()
                    # delete_sent_packets(sent_packets, ackNum)
                    # lock.release()
                elif (ackNum == lastAckNo): # dupACK
                    dup_ack_counter = dup_ack_counter + 1
                    if (dup_ack_counter >= 3):
                        # print("Need to retransmit!!")
                        # retransmit
                        message = randStr(N=10) # new message is generated
                        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
                        tcp_pkt = P4tcp(dstPort=1234, srcPort=2345, seqNo=ackNum, ackNo=1, dataPayload=message)
                        pkt = pkt / IP(dst=addr, proto=P4TCP_PROTOCOL) / tcp_pkt
                        sendp(pkt, iface=iface, verbose=False) 
                        # reduce cwnd - TCP Reno: cwnd = cwnd / 2 and sstresh = cwnd
                        cwnd = max(1, cwnd / 2)
                        ssthresh = cwnd
                        # lock.acquire()
                        # currently_sent = currently_sent + 1
                        # lock.release()

                lock.acquire()
                currently_sent = currently_sent - 1
                lock.release()

    sniff(iface = iface, prn = lambda x: handle_ack(x, addr, iface))

def main():
    iface = 'eth0'

    if len(sys.argv) < 2:
        print 'pass 1 argument: <destination>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    thread1 = threading.Thread(target=send_thread, args=(addr,iface,))
    thread2 = threading.Thread(target=ack_thread, args=(addr, iface))
    thread1.start()
    thread2.start()
    

if __name__ == '__main__':
    main()
