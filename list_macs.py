#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "Thomas AMORIM"
__credits__ = ["Thomas Amorim", "Pierre-François Bonnefoi" "Scapy"]
__license__ = "MIT"
__version__ = "1"
__status__ = "OK"

from scapy.all import *
import re, sys

liste_macs = []
dico_oui={}

re_oui = re.compile(r"([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s*\(hex\)\s*([^\s].*$)")

def traiter_paquet(t):
	if not ARP in t:
		return
	adresse_mac = t[Ether].src
	if not adresse_mac in liste_macs:
		liste_macs.append(adresse_mac)
		if adresse_mac[:8].upper() in dico_oui:
			print adresse_mac, " ", dico_oui[adresse_mac[:8].upper()]
		else:
			print adresse_mac

def init_dico_oui():
	global init_dico_oui
	f=open('oui.txt','r')
	while 1:
		ligne=f.readline()
		if not ligne :break
		resultat = re_oui.search(ligne)
		if resultat:
			am=resultat.group(1)+":"+resultat.group(2)+":"+resultat.group(3)
			dico_oui[am]=resultat.group(4)
	f.close()

def sniff_wifi_devices():
	def 
	if not t.haslayer(Dot11):
		return
	addr = t[Dot11].addr2
	if not addr in list_mac_detected:
		list_mac_detected.append(addr)
		print "New machine on ",addr

def save_to_file(filename):
	macs_file = open(filename, "w+")
	for mac in liste_macs:
		macs_file.write(mac+"\n")
	macs_file.close()

def force_arp(ipslash):
	p = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:03:24:45:11:34")/ARP(op="who-has",hwsrc="00:03:24:45:11:34",psrc="192.168.1.0",pdst=ipslash)
	sendp(p)

#can be detected
def scan_contact(ipslash):
	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipslash),timeout=2)
	for t in ans:
		adresse_mac = t[1][Ether].src
		if not adresse_mac in liste_macs:
			liste_macs.append(adresse_mac)
			if adresse_mac[:8].upper() in dico_oui:
				print adresse_mac, " ", dico_oui[adresse_mac[:8].upper()]
			else:
				print adresse_mac

if __name__ == "__main__":
	init_dico_oui()
	defaut_ip = "192.168.1.0/24"
	if len(sys.argv)!=1:
		defaut_ip = sys.argv[1] or defaut_ip
	#force_arp("192.168.1.0/24")
	#sniff(count=1000, filter="arp", prn=traiter_paquet)
	scan_contact(defaut_ip)
	save_to_file("listofmacs")