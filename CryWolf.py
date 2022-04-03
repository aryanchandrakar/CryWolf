#!/usr/bin/env python
import scanner_python3 as scanner #python 3
import scapy.all as scapy
#for http packets
from scapy.layers import http
from colorama import init, Fore, Back, Style


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        website=get_url(packet)
        target_url="http://"+website.decode()
        print(Style.BRIGHT+target_url)
        # return site
        # target_url = "http://10.0.2.9/dvwa/"
        # few looped links to ignore
        # target url will have links that log you out of the session, or other cases that stops the process
        links_to_ignore= ["http://10.0.2.9/dvwa/logout.php","http://testphp.vulnweb.com/logout.php"]
        data_dict = {"username": "admin", "password": "password","Login": "submit"}
        data_dict_vulnweb = {"uname": "test", "pass": "test", "login": "submit"}
        if ("10.0.2.9/dvwa/" in target_url):
            vuln_scanner = scanner.Scanner(target_url, links_to_ignore)
            response = vuln_scanner.session.post("http://10.0.2.9/dvwa/login.php", data=data_dict)
        elif ("testphp.vulnweb.com/" in target_url):
            vuln_scanner = scanner.Scanner(target_url, links_to_ignore)
            response = vuln_scanner.session.post("http://testphp.vulnweb.com/login.php", data=data_dict_vulnweb)
        # data is used to login, once logged in will not loose the session cause it's stored in the session url
        try:
            vuln_scanner.crawl()
            vuln_scanner.run_scanner()
        except Exception:
            pass


sniff("eth0")
