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
#include "includes/parser.p4"



#include "includes/l3.p4"
//#include "includes/custom_headers.p4"


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

action rewrite_dstAddrTCP(ipv4Addr, port) {
    modify_field(ipv4.dstAddr, ipv4Addr);
    modify_field(tcp.dstPort, port);
}

table rev_nat_tcp {
    reads {
        ipv4.dstAddr : exact;
        tcp.dstPort : exact;
    }
    actions {
        rewrite_dstAddrTCP;
        _drop;
    }
    size: REV_NAT_SIZE;
}

action rewrite_srcAddrTCP(ipv4Addr, port) {
    modify_field(ipv4.srcAddr, ipv4Addr);
    modify_field(tcp.srcPort, port);
}


#define CPU_SESSION_PORT  3
action send_to_cpu() {
    modify_field(standard_metadata.egress_spec, CPU_SESSION_PORT);
}

table fwd_nat_tcp {
    reads {
        ipv4.srcAddr : exact;
        tcp.srcPort : exact;
    }
    actions {
        rewrite_srcAddrTCP;
        send_to_cpu; //default action
    }
    size: FWD_NAT_SIZE;
}


#define CPU_MIRROR_SESSION_ID                  250
field_list copy_to_cpu_fields {
    standard_metadata;
}

// This is nop action to store an entry into the table
action reg() {
    modify_field(standard_metadata.egress_spec, 1);
}

table match_nat_ip {
    reads {
        ipv4.srcAddr : lpm;
    }
    actions {
        reg;
    }
}


control ingress {
    if(valid(ipv4) and ipv4.ttl > 0) {
        //Check if dest IPv4 address belongs to us
        if(valid(tcp)) {
            apply(match_nat_ip);//{
                //hit {
                //    apply(rev_nat_tcp);
               // }
            //}
        }
        else
        {
        // TODO: else if udp
        apply(ipv4_lpm);
        apply(forward);
        }
    }
}

control egress {
    if(valid(tcp)) {
        apply(fwd_nat_tcp);
    }
    apply(send_frame);
}




/*parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800
#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define ROUTER_IPV4 "10.0.2.10"


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
//        IP_PROTOCOLS_ICMP : parse_icmp;
        IP_PROTOCOLS_TCP : parse_tcp;
//        IP_PROTOCOLS_UDP : parse_udp;
        default: ingress;
    }
}

parser parse_tcp {
    //extract(tcp);
    return ingress;
}

// TODO: 
//parser parse_udp {
//    extract(udp);
//    return ingress;
//}

*/