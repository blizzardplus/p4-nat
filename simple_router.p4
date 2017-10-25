/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "p4_table_sizes.h"
#include "includes/headers.p4"
#include "includes/custom_headers.p4"


parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800
#define IP_PROT_TCP 0x06
#define IP_PROT_UDP 0x11

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROT_TCP : parse_tcp;
        IP_PROT_UDP : parse_udp;
        default : ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    return ingress;
}

parser parse_udp {
    extract(udp);
    return ingress;
}


field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        meta.tcpLength;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags;
        tcp.window;
        tcp.urgentPtr;
        payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    verify tcp_checksum if(valid(tcp));
    update tcp_checksum if(valid(tcp));
}


action _drop() {
    drop();
}

header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
    }
}

metadata routing_metadata_t routing_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

control ingress {
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(ipv4_lpm);
        apply(forward);
    }
}

control egress {
    apply(send_frame);
}




/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/



action nop() {
}

action on_miss() {
}

/*
 * NAT processing
 */

header_type nat_metadata_t {
    fields {
        ingress_nat_mode : 2;          /* 0: none, 1: inside, 2: outside */
        egress_nat_mode : 2;           /* nat mode of egress_bd */
        nat_nexthop : 16;              /* next hop from nat */
        nat_nexthop_type : 2;          /* ecmp or nexthop */
        nat_hit : 1;                   /* fwd and rewrite info from nat */
        nat_rewrite_index : 14;        /* NAT rewrite index */
        update_checksum : 1;           /* update tcp/udp checksum */
        update_inner_checksum : 1;     /* update inner tcp/udp checksum */
        l4_len : 16;                   /* l4 length */
    }
}

metadata nat_metadata_t nat_metadata;

#ifndef NAT_DISABLE
/*****************************************************************************/
/* Ingress NAT lookup - src, dst, twice                                      */
/*****************************************************************************/
/*
 * packet has matched source nat binding, provide rewrite index for source
 * ip/port rewrite
 */
action set_src_nat_rewrite_index(nat_rewrite_index) {
    modify_field(nat_metadata.nat_rewrite_index, nat_rewrite_index);
}

/*
 * packet has matched destination nat binding, provide nexthop index for
 * forwarding and rewrite index for destination ip/port rewrite
 */
action set_dst_nat_nexthop_index(nexthop_index, nexthop_type,
                                 nat_rewrite_index) {
    modify_field(nat_metadata.nat_nexthop, nexthop_index);
    modify_field(nat_metadata.nat_nexthop_type, nexthop_type);
    modify_field(nat_metadata.nat_rewrite_index, nat_rewrite_index);
    modify_field(nat_metadata.nat_hit, TRUE);
}

/*
 * packet has matched twice nat binding, provide nexthop index for forwarding,
 * and rewrite index for source and destination ip/port rewrite
 */
action set_twice_nat_nexthop_index(nexthop_index, nexthop_type,
                                   nat_rewrite_index) {
    modify_field(nat_metadata.nat_nexthop, nexthop_index);
    modify_field(nat_metadata.nat_nexthop_type, nexthop_type);
    modify_field(nat_metadata.nat_rewrite_index, nat_rewrite_index);
    modify_field(nat_metadata.nat_hit, TRUE);
}

table nat_src {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_sa : exact;
        l3_metadata.lkp_ip_proto : exact;
        l3_metadata.lkp_l4_sport : exact;
    }
    actions {
        on_miss;
        set_src_nat_rewrite_index;
    }
    size : IP_NAT_TABLE_SIZE;
}

table nat_dst {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
        l3_metadata.lkp_ip_proto : exact;
        l3_metadata.lkp_l4_dport : exact;
    }
    actions {
        on_miss;
        set_dst_nat_nexthop_index;
    }
    size : IP_NAT_TABLE_SIZE;
}

table nat_twice {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_sa : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
        l3_metadata.lkp_ip_proto : exact;
        l3_metadata.lkp_l4_sport : exact;
        l3_metadata.lkp_l4_dport : exact;
    }
    actions {
        on_miss;
        set_twice_nat_nexthop_index;
    }
    size : IP_NAT_TABLE_SIZE;
}

table nat_flow {
    reads {
        l3_metadata.vrf : ternary;
        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_l4_sport : ternary;
        l3_metadata.lkp_l4_dport : ternary;
    }
    actions {
        nop;
        set_src_nat_rewrite_index;
        set_dst_nat_nexthop_index;
        set_twice_nat_nexthop_index;
    }
    size : IP_NAT_FLOW_TABLE_SIZE;
}
#endif /* NAT_DISABLE */

control process_ingress_nat {
#ifndef NAT_DISABLE
    apply(nat_twice) {
        on_miss {
            apply(nat_dst) {
                on_miss {
                    apply(nat_src) {
                        on_miss {
                            apply(nat_flow);
                        }
                    }
                }
            }
        }
    }
#endif /* NAT DISABLE */
}


/*****************************************************************************/
/* Egress NAT rewrite                                                        */
/*****************************************************************************/
#ifndef NAT_DISABLE
action nat_update_l4_checksum() {
    modify_field(nat_metadata.update_checksum, 1);
    add(nat_metadata.l4_len, ipv4.totalLen, -20);
}

action set_nat_src_rewrite(src_ip) {
    modify_field(ipv4.srcAddr, src_ip);
    nat_update_l4_checksum();
}

action set_nat_dst_rewrite(dst_ip) {
    modify_field(ipv4.dstAddr, dst_ip);
    nat_update_l4_checksum();
}

action set_nat_src_dst_rewrite(src_ip, dst_ip) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(ipv4.dstAddr, dst_ip);
    nat_update_l4_checksum();
}

action set_nat_src_udp_rewrite(src_ip, src_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(udp.srcPort, src_port);
    nat_update_l4_checksum();
}

action set_nat_dst_udp_rewrite(dst_ip, dst_port) {
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(udp.dstPort, dst_port);
    nat_update_l4_checksum();
}

action set_nat_src_dst_udp_rewrite(src_ip, dst_ip, src_port, dst_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(udp.srcPort, src_port);
    modify_field(udp.dstPort, dst_port);
    nat_update_l4_checksum();
}

action set_nat_src_tcp_rewrite(src_ip, src_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(tcp.srcPort, src_port);
    nat_update_l4_checksum();
}

action set_nat_dst_tcp_rewrite(dst_ip, dst_port) {
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(tcp.dstPort, dst_port);
    nat_update_l4_checksum();
}

action set_nat_src_dst_tcp_rewrite(src_ip, dst_ip, src_port, dst_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(tcp.srcPort, src_port);
    modify_field(tcp.dstPort, dst_port);
    nat_update_l4_checksum();
}

table egress_nat {
    reads {
        nat_metadata.nat_rewrite_index : exact;
    }
    actions {
        nop;
        set_nat_src_rewrite;
        set_nat_dst_rewrite;
        set_nat_src_dst_rewrite;
        set_nat_src_udp_rewrite;
        set_nat_dst_udp_rewrite;
        set_nat_src_dst_udp_rewrite;
        set_nat_src_tcp_rewrite;
        set_nat_dst_tcp_rewrite;
        set_nat_src_dst_tcp_rewrite;
    }
    size : EGRESS_NAT_TABLE_SIZE;
}
#endif /* NAT_DISABLE */

control process_egress_nat {
#ifndef NAT_DISABLE
    if ((nat_metadata.ingress_nat_mode != NAT_MODE_NONE) and
        (nat_metadata.ingress_nat_mode != nat_metadata.egress_nat_mode)) {
        apply(egress_nat);
    }
#endif /* NAT_DISABLE */
}
