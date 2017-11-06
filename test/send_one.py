#!/usr/bin/python
import sys

from scapy.all import *
interface=sys.argv[1]

p = Ether(dst="00:aa:bb:00:00:02") / IP(dst="10.1.0.10") / TCP(dport=44440, sport=33330) / "aaaaaaaaaaaaaaaaaaa"
# p.show()
hexdump(p)
sendp(p, iface = interface)
