from scapy.contrib.automotive import someip, someip_sd as sd
from collections import namedtuple
from scapy.layers.inet import IP, UDP, Ether
from scapy.all import *
from scapy.contrib import igmpv3

#load_contrib("igmpv3")

iface = namedtuple("iface", "name ip port ")
SERVER = iface(name="server", ip="192.168.0.10", port=30490)
CLIENT = iface(name="client", ip="192.168.0.11", port=30490)
MULTI = iface(name="multicast", ip="224.224.224.245", port=30490)
L_IP = "192.168.0.13"
SERVICE_ID = 0x0003
INST_ID = 0x0010
TTL = 0x30

#SomeIP-SD pakage
sdp = sd.SD()
s = someip.SOMEIP()

sdp.flags=0x00
sdp.entry_array = [sd.SDEntry_Service(type=sd.SDEntry_Service.TYPE_SRV_OFFERSERVICE, srv_id=SERVICE_ID, inst_id=INST_ID, n_opt_1=1, ttl=TTL)]
sdp.option_array = [sd.SDOption_IP4_EndPoint(addr=L_IP, port=30490, l4_proto=0x11)]

#IP Pakage
i = IP()
i.src = "192.168.0.13"
i.dst = "224.224.224.245"

#UDP Pakage
u = UDP()
u.sport = 30490
u.dport = 30490

#IGMPv3
ig= igmpv3.IGMPv3()
ig.type = 0x22

#Built it all
p=Ether()/i/u/sdp.getSomeip(True)
#p.add_payload(Raw(binascii.unhexlify('ffff8100000000300000000101010200c000000000000010010000100003001000000003000000000000000c00090400c0a8000a0011772d')))
p.show2()
sendp(p, iface='enp0s25')