#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Thomas AMORIM"
__credits__ = ["Thomas Amorim", "Pierre-François Bonnefoi" "Scapy"]
__license__ = "MIT"
__version__ = "1.1"
__status__ = "OK"

from scapy.all import *
import sys

def force_arp(ipslash):
	p = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:03:24:45:11:34")/ARP(hwsrc="00:03:24:45:11:34",psrc="192.168.1.0",pdst=ipslash)
	p.show2()
	send(p)

if __name__ == "__main__":
	defaut_ip = "192.168.1.0/24"
	if len(sys.argv)!=1:
		ip = sys.argv[1] or defaut_ip
	force_arp("192.168.1.0/24")