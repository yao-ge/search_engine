/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define FIND_STRING 0x6F14

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

header udp_t {
    bit<16>   sport;
    bit<16>   dport;
    bit<16>   length;
    bit<16>   checksum;
    bit<16>   is_initd;
    bit<16>   is_find;
    bit<256>  payload;
    //bit<16>   payload;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
}

register<bit<16>>(1)  find_start;
register<bit<16>>(1)  is_end;
register<bit<16>>(1)  re_count; 
register<bit<256>>(1) ps_value;
//register<bit<16>>(1) ps_value;
register<bit<16>>(1)  value_len;
register<bit<16>>(1)  is_init;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: add parser logic */
        transition parse_ethernet;
    }
	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType){
			TYPE_IPV4 : parse_ipv4;
			default : accept;
		}
	}
	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition parse_udp;
	}

    state parse_udp {
        packet.extract(hdr.udp);
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
    action drop() {
        //mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */
		standard_metadata.egress_spec = port;
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
		hdr.ethernet.dstAddr = dstAddr;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action start_add(bit<16> val) {
        bit<32> index = 0;
        bit<16> tmp = 0;
        find_start.read(tmp, index);
        tmp = tmp + val;
        find_start.write(index, tmp);
    }

    action scan_find() {
        bit<32> index = 0;
        bit<16> tmp_start = 0;
        bit<16> tmp_end = 0;
        bit<16> tmp_re = 0;
        find_start.read(tmp_start, index);
        tmp_end = tmp_start + 16;
        hdr.udp.is_find = (hdr.udp.payload[15:0] == FIND_STRING) ? (bit<16>)65535:(bit<16>)0;
        tmp_start = 16;
        start_add(tmp_start);
        bit<16> tmp = 1;
        is_end.write(index, tmp);
    }

    action determine_value(bit<256> val, bit<16> len){
    //action determine_value(bit<16> val, bit<16> len){
        if(val[15:0] == FIND_STRING)
        {
            hdr.udp.is_find = len - 16;
			hdr.udp.is_initd = 1;
        }
    }

    action init_value_length() {
        bit<256> tmp_value;
        //bit<16> tmp_value;
        bit<32> index = 0;
        //bit<16> tmp_length = 256;
        bit<16> tmp_length;
        ps_value.read(tmp_value, index);
        tmp_value = hdr.udp.payload;
        ps_value.write(index, tmp_value);
        value_len.read(tmp_length, index);
        tmp_length = 256;
        value_len.write(index, tmp_length);
        is_init.write(index, 1);
    }

    action value_shift_scan() {
        bit<256> tmp_value = 0;
        //bit<16> tmp_value = 0;
        bit<16>  tmp_length = 0;
        bit<32> index = 0;
        bit<8> shift = 1;
        ps_value.read(tmp_value, index);
        value_len.read(tmp_length, index);

        determine_value(tmp_value, tmp_length);
        if(hdr.udp.is_find == 65535){
            tmp_value = tmp_value >> shift;
            tmp_length = tmp_length - 1;
        }

        determine_value(tmp_value, tmp_length);
        if(hdr.udp.is_find == 65535){
            tmp_value = tmp_value >> shift;
            tmp_length = tmp_length - 1;
        }

        determine_value(tmp_value, tmp_length);
        if(hdr.udp.is_find == 65535){
            tmp_value = tmp_value >> shift;
            tmp_length = tmp_length - 1;
        }

        determine_value(tmp_value, tmp_length);
        if(hdr.udp.is_find == 65535){
            tmp_value = tmp_value >> shift;
            tmp_length = tmp_length - 1;
        }

        determine_value(tmp_value, tmp_length);
        if(hdr.udp.is_find == 65535){
            tmp_value = tmp_value >> shift;
            tmp_length = tmp_length - 1;
        }

        determine_value(tmp_value, tmp_length);
        if(hdr.udp.is_find == 65535){
            tmp_value = tmp_value >> shift;
            tmp_length = tmp_length - 1;
        }

        determine_value(tmp_value, tmp_length);
        if(hdr.udp.is_find == 65535){
            tmp_value = tmp_value >> shift;
            tmp_length = tmp_length - 1;
        }

        determine_value(tmp_value, tmp_length);
        if(hdr.udp.is_find == 65535){
            tmp_value = tmp_value >> shift;
            tmp_length = tmp_length - 1;
        }

        ps_value.write(index, tmp_value);
        value_len.write(index, tmp_length);
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
        default_action = NoAction();
    }
    
    apply {
        /* TODO: fix ingress control logic
         *  - ipv4_lpm should be applied only when IPv4 header is valid
         */
        ipv4_lpm.apply();
        bit<16> tmp_init;
        bit<16> tmp_length = 0;
        bit<32> index = 0;
        if(hdr.udp.is_initd == 0){
            is_init.write(index, 0);
			hdr.udp.is_initd = 1;
        }
        is_init.read(tmp_init, index);
        if(tmp_init == 0){
            hdr.ipv4.flags = 1;
            init_value_length();
        }
        value_len.read(tmp_length, index);
        if(tmp_length == 0){
            return;
        }
        value_shift_scan();
        if(hdr.udp.is_find == 65535){
			hdr.udp.is_find = 5;
			resubmit(meta);
        }

        //bit<16> tmp = 0;
        //bit<32> index = 0;
        //tmp = tmp + hdr.udp.payload;
        //ps_value.write(index, tmp);
        //tmp = tmp + tmp;
        //ps_value.write(index, tmp);
        //ps_value.read(tmp, index);
        //hdr.udp.payload = tmp;
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
    update_checksum_with_payload(
            hdr.udp.isValid(),
            {
            hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, hdr.ipv4.totalLen, 16w0xffeb,
            hdr.udp.sport,
            hdr.udp.dport,
            hdr.udp.length,
			hdr.udp.is_initd,
            hdr.udp.is_find,
            hdr.udp.payload
            },
            hdr.udp.checksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.udp);
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
