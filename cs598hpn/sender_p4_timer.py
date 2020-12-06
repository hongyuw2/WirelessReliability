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
RTO = 1

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

def send_packet(seq_no, iface, addr):
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    message = randStr(N=10)
    tcp_pkt = P4tcp(dstPort=1234, srcPort=2345, seqNo=seq_no, ackNo=1, dataPayload=message)
    pkt = pkt / IP(dst=addr, proto=P4TCP_PROTOCOL) / tcp_pkt
    sendp(pkt, iface=iface, verbose=False)
    # print_packet_send(tcp_pkt)
    return tcp_pkt


MAX_CWND = 200
NUM_PACKETS_TO_SEND =  300
INIT_CWND = 1

# SHARED VAR
cwnd = INIT_CWND
ssthresh = 150
currently_sent = 0
count_sent_packets = 0
lock = threading.Lock()
lastAckNo = 0
dup_ack_counter = 0
sent_packets = dict()

def rto_check(sent_packets, iface, addr):
    global lock, cwnd
    lock.acquire()
    for seq_no in sent_packets:
        if (sent_packets[seq_no] <= time.time()):
            # print("Retransmit seq : " + str(seq_no))
            send_packet(seq_no, iface, addr)
            sent_packets[seq_no] = sent_packets[seq_no] + RTO
            cwnd = INIT_CWND
    lock.release()

def print_packet_receive(tcp_pkt):
    print("Received packet SEQ= %d, ACK=%d" % (tcp_pkt.seqNo, tcp_pkt.ackNo))

def print_packet_send(tcp_pkt):
    print("Sent packet SEQ= %d, ACK=%d" % (tcp_pkt.seqNo, tcp_pkt.ackNo))

# Sending data
def send_thread(addr, iface):
    global cwnd, lock, sent_packets
    curr_seq_no = 1
    count_sent_packets = 0
    start_time = time.time()

    while True:
        if (len(sent_packets) < cwnd):
            tcp_pkt = send_packet(curr_seq_no, iface, addr)
            count_sent_packets = count_sent_packets + 1
            # print("Sent packets = " + str(count_sent_packets))
            lock.acquire()
            sent_packets[curr_seq_no] = time.time() + RTO
            lock.release()
            curr_seq_no = curr_seq_no + PAYLOAD_LENGTH
            if (count_sent_packets >= NUM_PACKETS_TO_SEND):
                break
        # Retransmission timer
        rto_check(sent_packets, iface, addr)

    while (len(sent_packets) > 0):
        # Retransmission timer
        rto_check(sent_packets, iface, addr)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print("Flow completion time: %f s, total packets : %d" % (elapsed_time, count_sent_packets))

# remove packets whose seq_num is less than ack_num
def remove_packet_from_buffer(sent_packets, ack_num):
    global lock
    lock.acquire()
    keys = [k for k, v in sent_packets.items() if k < ack_num]
    for x in keys:
        del sent_packets[x]
    lock.release()
    return len(keys)


# Getting ack packet, and set cwnd
def ack_thread(addr, iface):

    def handle_ack(pkt, addr, iface):
        global lock, cwnd, ssthresh, currently_sent, lastAckNo, dup_ack_counter, sent_packets
        if P4tcp in pkt:
            p4tcp = pkt[P4tcp]
            if (p4tcp.packetType == "A"): # ACK packet
                # print_packet_receive(p4tcp)
                ackNum = p4tcp.ackNo
                if (ackNum > lastAckNo):
                    lastAckNo = ackNum
                    acked_packets = remove_packet_from_buffer(sent_packets, ackNum)
                    for i in range (0, acked_packets):
                        if (cwnd <= ssthresh): # Slow start phase
                            cwnd = min(cwnd * 2, MAX_CWND)
                        else: # Congestion avoidance phase
                            cwnd = min(cwnd + 1, MAX_CWND)
                    dup_ack_counter = 0
                    print("Cwnd: %d, unacked_packet: %d" % (cwnd, len(sent_packets)))
                elif (ackNum == lastAckNo): # dupACK
                    # print("Dup ack!")
                    dup_ack_counter = dup_ack_counter + 1
                    if (dup_ack_counter >= 3):
                        # print("Need to retransmit!!")
                        # retransmit
                        tcp_pkt = send_packet(ackNum, iface, addr)
                        # reduce cwnd - TCP Reno: cwnd = cwnd / 2 and sstresh = cwnd
                        cwnd = max(INIT_CWND, cwnd / 2)
                        ssthresh = cwnd
                    # remove_packet_from_buffer(sent_packets, ackNum)
                # print("Latest ack number : " + str(lastAckNo))

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