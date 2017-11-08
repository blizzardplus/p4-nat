#!/usr/bin/env python
import sys
import struct
import os
import random
from Crypto import Random

from scapy.all import sniff, IP, TCP, UDP, Raw
from runtime_CLI import RuntimeAPI, get_parser, thrift_connect, load_json_config

from bm_runtime.standard.ttypes import *

NATIPv4 = "10.0.1.10"
tagSize = 2 # In bytes
global rAPI, rndDesc


#table_add fwd_nat_tcp rewrite_srcAddrTCP 10.0.1.10 33333 => 10.1.0.10 44444
#table_add rev_nat_tcp rewrite_dstAddrTCP 10.1.0.10 44444 => 10.0.1.10 33333

def addNATTables(rAPI, origIPv4, origSrcPort, natIPv4):
    fwdSuccess = revSuccess = False
    while not (fwdSuccess and revSuccess):
        fwdSuccess = revSuccess = False
        natSrcPort = 0
        try:
            if tagSize > 2:
                pass #What to do for larger tags?
            else:
                while natSrcPort < 2000:
                    tagCand = bytearray(rndDesc.read(tagSize))
                    natSrcPort = 256*tagCand[1] + tagCand[0]

                fwdtbl_str = "fwd_nat_tcp rewrite_srcAddrTCP {} {} => {} {}".format(origIPv4,
                 origSrcPort, natIPv4, natSrcPort)
                print fwdtbl_str
                rAPI.onecmd("table_add " + fwdtbl_str)
                fwdSuccess = True

                #Reverse table
                revtbl_str = "rev_nat_tcp rewrite_dstAddrTCP {} {} => {} {}".format(natIPv4,
                 natSrcPort, origIPv4, origSrcPort)
                print revtbl_str
                rAPI.onecmd("table_add " + revtbl_str)
                revSuccess = True
        except InvalidTableOperation as e:
            if e.code == TableOperationErrorCode.DUPLICATE_ENTRY:
                # Revert
                if fwdSuccess:
                    rAPI.onecmd("table_delete " + fwdtbl_str)
                if revSuccess:
                    rAPI.onecmd("table_delete " + revtbl_str)
                continue



def del_table_entry (args):
    pass

def handle_pkt(rAPI):
    def handle_pkt_func(pkt):
        print "got a packet"
        pkt.show2()
        if IP in pkt and TCP in pkt:
            addNATTables(rAPI, pkt[IP].dst, pkt[TCP].sport, NATIPv4)
        #hexdump(pkt)
        #sys.stdout.flush()
    return handle_pkt_func




def main():

    global rAPI, rndDesc

    args = get_parser().parse_args()

    standard_client, mc_client = thrift_connect(
        args.thrift_ip, args.thrift_port,
        RuntimeAPI.get_thrift_services(args.pre)
    )

    load_json_config(standard_client, args.json)

    rAPI = RuntimeAPI(args.pre, standard_client, mc_client)


    # PRNG
    rndDesc = Random.new()

    print "sniffing on %s" % args.iface
    sys.stdout.flush()
    sniff(iface = args.iface,
          prn = handle_pkt(rAPI))
    rndDesc.close()


if __name__ == '__main__':
    main()