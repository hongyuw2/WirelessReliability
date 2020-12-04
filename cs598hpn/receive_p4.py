#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sniff, sendp, send, srp1
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

def main():
    iface = 'eth0'

    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))


def handle_pkt(pkt):
    if P4tcp in pkt:
        print "got a packet"
        pkt.show2()
        sys.stdout.flush()


if __name__ == '__main__':
    main()
