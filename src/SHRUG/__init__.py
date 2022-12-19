from scapy.all import *
from yacryptopan import CryptoPAn
import random

cp = CryptoPAn(b'32-char-str-for-AES-key-and-pad.')

def has_ip(pkt):
  if "IP" in pkt:
    return 1
  else:
    return 0

def randomizer(pks):
    for packet in pks:
      if(has_ip(packet)):
        source_ip = packet.getlayer(IP).src
        destination_ip = packet.getlayer(IP).dst
    
      if source_ip:
        rnd_src = ""
        for j in range(4):
            num = random.SystemRandom().randint(1, 254)
            rnd_src += str(num)
            if j != 3:
                rnd_src += "."
        packet.getlayer(IP).src = str.encode(rnd_src)

      if destination_ip:
        rnd_dest = ""
        for j in range(4):
            num = random.SystemRandom().randint(1, 254)
            rnd_dest += str(num)
            if j != 3:
                rnd_dest += "."
        packet.getlayer(IP).dst = str.encode(rnd_dest)
      

def prefanon(pks):
  for packet in pks:
    if(has_ip(packet)):
      source_ip = packet.getlayer(IP).src
      destination_ip = packet.getlayer(IP).dst

      if source_ip:
        new_src = cp.anonymize(source_ip)
        packet.getlayer(IP).src = str.encode(new_src)

      if destination_ip:
        new_dst = cp.anonymize(destination_ip)
        packet.getlayer(IP).dst = str.encode(new_dst)
      

def read_from(filename):
    return rdpcap(filename)

def write_to(filename, pks):
    wrpcap(filename, pks)


pks = read_from("../ipv4frags.pcap")
randomizer(pks)
write_to("randomizer-pref.pcap", pks)