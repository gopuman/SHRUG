from scapy.all import *
from yacryptopan import CryptoPAn
import random
import numpy as np

#Check whether the packet within the capture contains src/dst fields
def has_ip(pkt):
  if "IP" in pkt:
    return 1
  else:
    return 0

#Reading a .pcap or .tcpdump file
def read_from(filename):
    return rdpcap(filename)

#Write the modified packets into a file
def write_to(filename, pks):
    wrpcap(filename, pks)

#Randomization algorithm
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

#CryptoPAn algorithm
def prefAnon(pks):
  cp = CryptoPAn(b'32-char-str-for-AES-key-and-pad.')
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

#BlackMarker Algorithm
def blackMarker(pks):
  for packet in pks:
    if(has_ip(packet)):
      source_ip = packet.getlayer(IP).src
      destination_ip = packet.getlayer(IP).dst

      if source_ip:
        packet.getlayer(IP).src = str.encode("0.0.0.0")

      if destination_ip:
        packet.getlayer(IP).dst = str.encode('0.0.0.0')

#Permutation Algorithm 
def permutation(pks):
  for packet in pks:
    if(has_ip(packet)):
      source_ip = packet.getlayer(IP).src
      destination_ip = packet.getlayer(IP).dst

      if source_ip:
        source_ip = source_ip.split(".")
        perm_src = np.random.permutation(source_ip)
        packet.getlayer(IP).src = str.encode('.'.join(perm_src))

      if destination_ip:
        destination_ip = destination_ip.split(".")
        perm_dst = np.random.permutation(destination_ip)
        packet.getlayer(IP).dst = str.encode('.'.join(perm_dst))

#Helper function for truncation algo
def setToZero(arr, num):
  ind = 3 - (num // 8)
  mod = num % 8
  for i in range(ind+1, 4):
    arr[i] = 0
  mask = ~((1 << mod)-1)
  arr[ind] &= mask
  return arr

#Truncation Algorithm
def truncation(pks, n):
  for packet in pks:
    if(has_ip(packet)):
      source_ip = packet.getlayer(IP).src
      destination_ip = packet.getlayer(IP).dst

      if source_ip:
        source_ip = source_ip.split(".")
        source_ip = [int(x) for x in source_ip]
        source_ip = setToZero(source_ip, n)    
        source_ip = [str(x) for x in source_ip]
        packet.getlayer(IP).src = str.encode('.'.join(source_ip))

      if destination_ip:
        destination_ip = destination_ip.split(".")
        destination_ip = [int(x) for x in destination_ip]
        destination_ip = setToZero(destination_ip, n)    
        destination_ip = [str(x) for x in destination_ip]
        packet.getlayer(IP).dst = str.encode('.'.join(destination_ip))     

def rev_setToZero(arr, num):
  ind = (num // 8)
  mod = num % 8
  for i in range(0, ind):
    arr[i] = 0
  mod = 32 - mod
  mask = ((1 << mod)-1)
  arr[ind] &= mask
  return arr

#Reverse Truncation Algorithm
def revTruncation(pks, n):
  for packet in pks:
    if(has_ip(packet)):
      source_ip = packet.getlayer(IP).src
      destination_ip = packet.getlayer(IP).dst

      if source_ip:
        source_ip = source_ip.split(".")
        source_ip = [int(x) for x in source_ip]
        source_ip = rev_setToZero(source_ip, n)    
        source_ip = [str(x) for x in source_ip]
        packet.getlayer(IP).src = str.encode('.'.join(source_ip))

      if destination_ip:
        destination_ip = destination_ip.split(".")
        destination_ip = [int(x) for x in destination_ip]
        destination_ip = rev_setToZero(destination_ip, n)    
        destination_ip = [str(x) for x in destination_ip]
        packet.getlayer(IP).dst = str.encode('.'.join(destination_ip))         
            

pks = read_from("../../../ipv4frags-randomizer.pcap")
truncation(pks,12)
write_to("randomizer-pref.pcap", pks)