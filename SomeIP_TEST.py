#from scapy.contrib.automotive import someip as si
from scapy.contrib.automotive.someip import SOMEIP
from scapy.layers.inet import IP, UDP
from scapy.all import *
load_contrib("automotive.someip")

s = SOMEIP()


sip = SOMEIP()

u = UDP()

i = IP()

u.sport = 30509
u.dport = 30509

i.src = "192.168.0.13"
i.dst = "192.168.0.10"

sip.iface_ver = 0

sip.proto_ver = 0

sip.msg_type = "REQUEST"

sip.retcode = "E_OK"

sip.msg_id.srv_id = 0x0003

sip.msg_id.method_id = 0x0100

sip.add_payload(Raw ("Hello"))

p  = i/u/sip

sendp(p)
