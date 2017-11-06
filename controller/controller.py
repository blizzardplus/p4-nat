#!/usr/bin/env python
import sys
import struct
import os
import random

from scapy.all import sniff, IP, TCP, UDP, Raw
from runtime_CLI import RuntimeAPI, get_parser, thrift_connect, load_json_config

NATIPv4 = "10.0.1.10"

#table_add fwd_nat_tcp rewrite_srcAddrTCP 10.0.1.10 33333 => 10.1.0.10 44444
#table_add rev_nat_tcp rewrite_dstAddrTCP 10.1.0.10 44444 => 10.0.1.10 33333

def addNATTables(rAPI, origIPv4, origSrcPort, natIPv4, natSrcPort):
    fwdtbl_str = "table_add fwd_nat_tcp rewrite_srcAddrTCP {} {} => {} {}".format(origIPv4,
     origSrcPort, natIPv4, natSrcPort)
    print fwdtbl_str
    revtbl_str = "table_add rev_nat_tcp rewrite_dstAddrTCP {} {} => {} {}".format(natIPv4,
     natSrcPort, origIPv4, origSrcPort)
    print revtbl_str
    rAPI.onecmd(fwdtbl_str)
    rAPI.onecmd(revtbl_str)

def del_table_entry (args):
    pass

def handle_pkt(rAPI):
    def handle_pkt_func(pkt):
        print "got a packet"
        pkt.show2()
        if IP in pkt and TCP in pkt:
            addNATTables(rAPI, pkt[IP].dst, pkt[TCP].sport, NATIPv4, random.randint(20000,65535))
        #hexdump(pkt)
        #sys.stdout.flush()
    return handle_pkt_func


global rAPI

def main():
    args = get_parser().parse_args()

    standard_client, mc_client = thrift_connect(
        args.thrift_ip, args.thrift_port,
        RuntimeAPI.get_thrift_services(args.pre)
    )

    load_json_config(standard_client, args.json)

    rAPI = RuntimeAPI(args.pre, standard_client, mc_client)

    print "sniffing on %s" % args.iface
    sys.stdout.flush()
    sniff(iface = args.iface,
          prn = handle_pkt(rAPI))



if __name__ == '__main__':
    main()