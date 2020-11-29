/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP = 6;

#define BLOOM_FILTER_ENTRIES 4096
#define PAYLOAD_SIZE 5792

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header payload_t {
    bit<PAYLOAD_SIZE> data;
}


struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    payload_t    payload;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
       packet.extract(hdr.tcp);
       transition parse_payload;
    }

    state parse_payload {
        packet.extract(hdr.payload);
        transition accept;
    }
    
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<PAYLOAD_SIZE>>(BLOOM_FILTER_ENTRIES) cache_payload;
    bit<32> reg_pos;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action compute_hashes(ip4Addr_t src_ip, ip4Addr_t dst_ip, bit<16> src_port, bit<16> dst_port, bit<32> seqNo) {
       //Get register position
       hash(reg_pos, HashAlgorithm.crc16, (bit<32>)0, {src_ip, dst_ip, src_port, dst_port, seqNo}, (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action redirect_packet(macAddr_t srcAddr, macAddr_t dstAddr, ip4Addr_t src_ip, ip4Addr_t dst_ip, bit<16> src_port, bit<16> dst_port) {
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.srcAddr = src_ip;
        hdr.ipv4.dstAddr = dst_ip;
        hdr.tcp.src_port = src_port;
        hdr.tcp.dst_port = dst_port;
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

    // Table for debugging purpose, just put any data to its key and it will show up on the log file
    table debug_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.tcp.syn: exact;
        }
        actions = { NoAction; }
        const default_action = NoAction;
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            /*
            1. Check whether this packet is data packet (packet that contains payload)
            2. If yes, store the payload using the bloom filter and register arrays -> see the firewall implementation. 
                We can use the hash just like them. Perhaps, the key will be dst_ip, src_ip, dst_port, src_port, and tcp_seq_num.
            3. If no, check whether this packet is a signal to retransmission (check it's SACK option or duplicate ACKs). 
                If it is a signal packet, drop this, look at your cache (look at this packet ack number and try to match it with seq number),
                modify the packet header (ethernet, ipv4, and tcp headers), put the payload, and forward it back to the sender.  
            4. Otherwise, do nothing -- it will just forward the packet using ipv4_forward
            */
            if (hdr.tcp.isValid()) {
                // TODO: identify data packet
                if (hdr.payload.data == 0) { // Check whether this packet is data packet (packet that contains payload)
                    // TODO: identify SACK
                    if () {
                        // Rewrite payload
                        compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort, hdr.tcp.ackNo);
                        cache_payload.read(reg_pos, hdr.payload.data);

                        // Fill in addrs and ports
                        redirect_packet(hdr.ethernet.dstAddr, hdr.ethernet.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort);

                        // TODO: adjust TCP headers
                    }
                }
                else {
                    compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo);
                    cache_payload.write(reg_pos, hdr.payload.data);
                }
            }
            ipv4_lpm.apply();
        }
        debug_table.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
        
        // TODO: modify the following TCP checksum calc OR cache TCP checksum
        update_checksum(
            hdr.ipv4.isValid(),
            { ipv4.srcAddr;
              ipv4.dstAddr;
              8'0;
              ipv4.protocol;
              routing_metadata.tcpLength; // TODO
              hdr.tcp.srcPort;
              hdr.tcp.dstPort;
              hdr.tcp.seqNo;
              hdr.tcp.ackNo;
              hdr.tcp.dataOffset,
              hdr.tcp.res,
              hdr.tcp.ecn,  // TODO
              hdr.tcp.ctrl, // TODO
              hdr.tcp.window,
              hdr.tcp.urgentPtr,
              hdr.payload.data },
            hdr.tcp.checksum,
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
        packet.emit(hdr.payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
