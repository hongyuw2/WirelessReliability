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

typedef bit<160> raw_ipv4_t;
typedef bit<160> raw_tcp_t;

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
    
    register<raw_ipv4_t>(BLOOM_FILTER_ENTRIES) cache_ip_hdr;
    register<raw_tcp_t>(BLOOM_FILTER_ENTRIES) cache_tcp_hdr;
    register<bit<PAYLOAD_SIZE>>(BLOOM_FILTER_ENTRIES) cache_payload;
    bit<32> reg_pos;
    raw_ipv4_t raw_ipv4_hdr;
    raw_tcp_t raw_tcp_hdr;

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
       // Get register position
       hash(reg_pos, HashAlgorithm.crc16, (bit<32>)0, {src_ip, dst_ip, src_port, dst_port, seqNo}, (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action generate_ip_hdr() {
        cache_ip_hdr.read(raw_ipv4_hdr, reg_pos);

        hdr.ipv4.version            = raw_ipv4_hdr[3:0];
        hdr.ipv4.ihl                = raw_ipv4_hdr[7:4];
        hdr.ipv4.diffserv           = raw_ipv4_hdr[15:8];
        hdr.ipv4.totalLen           = raw_ipv4_hdr[31:16];
        hdr.ipv4.identification     = raw_ipv4_hdr[47:32];
        hdr.ipv4.flags              = raw_ipv4_hdr[50:48];
        hdr.ipv4.fragOffset         = raw_ipv4_hdr[63:51];
        hdr.ipv4.ttl                = raw_ipv4_hdr[71:64];
        hdr.ipv4.protocol           = raw_ipv4_hdr[79:72];
        hdr.ipv4.hdrChecksum        = raw_ipv4_hdr[95:80];
        hdr.ipv4.srcAddr            = raw_ipv4_hdr[127:96];
        hdr.ipv4.dstAddr            = raw_ipv4_hdr[159:128];
    }

    action record_ip_hdr() {
        raw_ipv4_hdr[3:0]           = hdr.ipv4.version;
        raw_ipv4_hdr[7:4]           = hdr.ipv4.ihl;
        raw_ipv4_hdr[15:8]          = hdr.ipv4.diffserv;
        raw_ipv4_hdr[31:16]         = hdr.ipv4.totalLen;
        raw_ipv4_hdr[47:32]         = hdr.ipv4.identification;
        raw_ipv4_hdr[50:48]         = hdr.ipv4.flags;
        raw_ipv4_hdr[63:51]         = hdr.ipv4.fragOffset;
        raw_ipv4_hdr[71:64]         = hdr.ipv4.ttl;
        raw_ipv4_hdr[79:72]         = hdr.ipv4.protocol;
        raw_ipv4_hdr[95:80]         = hdr.ipv4.hdrChecksum;
        raw_ipv4_hdr[127:96]        = hdr.ipv4.srcAddr;
        raw_ipv4_hdr[159:128]       = hdr.ipv4.dstAddr;

        cache_ip_hdr.write(reg_pos, raw_ipv4_hdr);
    }

    action generate_tcp_hdr() {
        cache_tcp_hdr.read(raw_tcp_hdr, reg_pos);

        hdr.tcp.srcPort     = raw_tcp_hdr[15:0];
        hdr.tcp.dstPort     = raw_tcp_hdr[31:16];
        hdr.tcp.seqNo       = raw_tcp_hdr[63:32];
        hdr.tcp.ackNo       = raw_tcp_hdr[95:64];
        hdr.tcp.dataOffset  = raw_tcp_hdr[99:96];
        hdr.tcp.res         = raw_tcp_hdr[103:100];
        hdr.tcp.cwr         = raw_tcp_hdr[104:104];
        hdr.tcp.ece         = raw_tcp_hdr[105:105];
        hdr.tcp.urg         = raw_tcp_hdr[106:106];
        hdr.tcp.ack         = raw_tcp_hdr[107:107];
        hdr.tcp.psh         = raw_tcp_hdr[108:108];
        hdr.tcp.rst         = raw_tcp_hdr[109:109];
        hdr.tcp.syn         = raw_tcp_hdr[110:110];
        hdr.tcp.fin         = raw_tcp_hdr[111:111];
        hdr.tcp.window      = raw_tcp_hdr[127:112];
        hdr.tcp.checksum    = raw_tcp_hdr[143:128];
        hdr.tcp.urgentPtr   = raw_tcp_hdr[159:144];
    }

    action record_tcp_hdr() {
        raw_tcp_hdr[15:0]       = hdr.tcp.srcPort;
        raw_tcp_hdr[31:16]      = hdr.tcp.dstPort;
        raw_tcp_hdr[63:32]      = hdr.tcp.seqNo;
        raw_tcp_hdr[95:64]      = hdr.tcp.ackNo;
        raw_tcp_hdr[99:96]      = hdr.tcp.dataOffset;
        raw_tcp_hdr[103:100]    = hdr.tcp.res;
        raw_tcp_hdr[104:104]    = hdr.tcp.cwr;
        raw_tcp_hdr[105:105]    = hdr.tcp.ece;
        raw_tcp_hdr[106:106]    = hdr.tcp.urg;
        raw_tcp_hdr[107:107]    = hdr.tcp.ack;
        raw_tcp_hdr[108:108]    = hdr.tcp.psh;
        raw_tcp_hdr[109:109]    = hdr.tcp.rst;
        raw_tcp_hdr[110:110]    = hdr.tcp.syn;
        raw_tcp_hdr[111:111]    = hdr.tcp.fin;
        raw_tcp_hdr[127:112]    = hdr.tcp.window;
        raw_tcp_hdr[143:128]    = hdr.tcp.checksum;
        raw_tcp_hdr[159:144]    = hdr.tcp.urgentPtr;

        cache_tcp_hdr.write(reg_pos, raw_tcp_hdr);
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

    table ackNo_table {
        key = {
            // hdr.ipv4.srcAddr: lpm;
            hdr.ipv4.dstAddr: lpm;
            hdr.tcp.srcPort: exact;
            hdr.tcp.dstPort: exact;
            hdr.tcp.ackNo: exact;
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
                // Check whether this packet is data packet (packet that contains payload)
                if (hdr.ipv4.totalLen == (bit<16>)(hdr.ipv4.ihl + hdr.tcp.dataOffset)) { 
                    // Identify dup ACK
                    if (ackNo_table.apply().hit) {
                        // Rewrite payload and headers
                        compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort, hdr.tcp.ackNo);

                        generate_ip_hdr();
                        generate_tcp_hdr();
                        cache_payload.read(hdr.payload.data, reg_pos);

                        // Redirect Ethernet addr and out port
                        ipv4_forward(hdr.ethernet.srcAddr, standard_metadata.ingress_port);
                    }
                }
                else {
                    compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo);
                    cache_payload.write(reg_pos, hdr.payload.data);
                    record_tcp_hdr();
                    record_ip_hdr();
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
