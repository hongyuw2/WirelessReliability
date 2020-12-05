/* -*- P4_16 -*- */

/*
 * P4 TCP
 *
 * This program implements a simple protocol. It can be carried over IP
 * (Protocol TYPE_P4TCP).
 */

#include <core.p4>
#include <v1model.p4>

/*
 * Define the headers the program will recognize
 */

// 1454 bytes = 1000*8 
#define PAYLOAD_SIZE 8000

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*
 * Standard ethernet header 
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/*
 * This is a custom protocol header for the tcp-p4. We'll use 
 * ethertype 0x1234 for is (see parser)
 */
const bit<8>  P4TCP_P     = 0x50;   // 'P'
const bit<8>  P4TCP_4     = 0x34;   // '4'
const bit<8>  P4TCP_VER   = 0x01;   // v0.1
const bit<8>  TYPE_P4TCP  = 0x09;
const bit<16> TYPE_IPV4 = 0x800;

header p4tcp_t {
    bit<8>  p;
    bit<8>  four;
    bit<8>  ver;
    bit<8>  packetType;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<PAYLOAD_SIZE> payload;
}

/*
 * All headers, used in the program needs to be assembed into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    p4tcp_t     tcp;
}

/*
 * All metadata, globally used in the program, also  needs to be assembed 
 * into a single struct. As in the case of the headers, we only need to 
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
 
struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default      : accept;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_P4TCP: check_p4tcp;
            default: accept;
        }
    }

    state check_p4tcp {
        transition select(packet.lookahead<p4tcp_t>().p,
        packet.lookahead<p4tcp_t>().four,
        packet.lookahead<p4tcp_t>().ver) {
            (P4TCP_P, P4TCP_4, P4TCP_VER) : parse_p4tcp;
            default                          : accept;
        }
    }
    
    state parse_p4tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // action send_back() {
    //     bit<48> tmp;
        
    //     /* Swap the MAC addresses */
    //     tmp = hdr.ethernet.dstAddr;
    //     hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
    //     hdr.ethernet.srcAddr = tmp;
        
    //     /* Send the packet back to the port it came from */
    //     standard_metadata.egress_spec = standard_metadata.ingress_port;
    // }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table debug_table {
        key = {
            hdr.tcp.packetType : exact;
            hdr.tcp.srcPort : exact;
            hdr.tcp.dstPort : exact;
            hdr.tcp.seqNo : exact;
            hdr.tcp.ackNo : exact;
            hdr.tcp.payload : exact;
        }
        actions = { NoAction; }
        const default_action = NoAction;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid()) {
                debug_table.apply();
            }
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;