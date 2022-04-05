import os
import signal
import ssl
import webbrowser
import re
from colorama import init, Fore, Back, Style
import requests
import sys


def ssl_result(packet):
    target_url=packet
    print(Fore.BLUE+target_url+Style.RESET_ALL)
    vulnerable(target_url)

def vulnerable(link):
    SSL_issue = ssl_verify(link)
    if SSL_issue:
        alert_process_SSL()
        print(Fore.YELLOW+"[+] For safety no further steps being taken."+Style.RESET_ALL)
    print("")


def alert_process_SSL():
    for i in (os.popen("ps ax | grep firefox | grep -v grep")):
        field = i.split()
        pid = field[0]
        os.kill(int(pid), signal.SIGKILL)
    webbrowser.open_new_tab("indexSSL.html")
def ssl_verify(link):
    try:
        requests.get(link, verify='/etc/ssl/certs/ca-certificates.crt')
        print(Style.BRIGHT +  Fore.GREEN +"[+] Verified "+Style.RESET_ALL)
        return False
    except requests.exceptions.SSLError as se:
        reason = (str(se).split('"')[1])  # reason-bad handshake
        caused_by = re.search("Caused by [\w]*", str(se)).group()  # cause by
        caused = str(re.search("Caused by SSLError[^a-z][\w]*", str(se)).group()).split("(")[1]  # cause
        print(Style.BRIGHT + Fore.RED + Back.WHITE +
              "[-] Insecure Transport (SSL error) vulnerability discovered in: " + link + Style.RESET_ALL)
        print(Fore.BLACK + Back.RED + caused_by+ Style.RESET_ALL)
        print(Fore.BLACK + Back.RED+ caused+ Style.RESET_ALL)
        print(Fore.RED + reason)
        return True
    except Exception as e:
        print("[!] Faced some irregular issue. Continuing...")
        return False


ssl_result('https://github.com/')
ssl_result('https://expired.badssl.com/') # Expired SSL
ssl_result('https://wrong.host.badssl.com/') # Wrong host
ssl_result('https://untrusted-root.badssl.com/') # untrusted root
sys.exit(" -- GOODBYE! -- ")

