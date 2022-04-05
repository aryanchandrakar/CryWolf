#!/usr/bin/env python
import os
import signal
import sys
import webbrowser

import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style


class Scanner:
    def __init__(self,url,ignore_links):
        self.session=requests.Session() # represent current session, everything will be done through out the session
        self.target_url=url
        self.target_links=[]
        self.links_ingore=ignore_links

    def extract_links(self,url):
        response = self.session.get(url)
        re_code='(?:href=")(.*?)"'
        return re.findall(re_code.encode(), response.content)

    def crawl(self,url=None): # default value of url is none, can call the method without specifying the url
        if url==None:
            url=self.target_url # if the method is called without the url, it checks and set the url to target url
        href_links = self.extract_links(url)
        for i in href_links: # i is the link
            i = urllib.parse.urljoin(url, i.decode()) # only completes the incomplete links leaves the rest
            if '#' in i:
                i = i.split('#')[0]
            if self.target_url in i and i not in self.target_links and i not in self.links_ingore:
                # won't crawl the ignored links cause we don't wanna stop process
                self.target_links.append(i)
                print(i)
                self.crawl(i)  # recursive function to crawl within the link, to crawl everything in website

    def extract_forms(self,url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content,'html.parser')  # using this to access different part of html page
        return parsed_html.findAll("form")  # element in the form is given, with all the nested elements

    def submit_for(self,form,value,url): # submit the forms
        # .get to get the attributes
        action = form.get("action")
        post_url = urllib.parse.urljoin(url, action)  # to complete the url
        # print(post_url)
        method = form.get("method")
        input_list = form.findAll("input")
        post_data = {}  # creating a dictionary to pass the value
        for input in input_list:
            # getting the attributes in the attribute
            input_name = input.get("name")
            # print(input_name)
            input_type = input.get("type")
            input_value = input.get("value")  # default value just in case
            if input_type == "text":
                input_value = value
            post_data[input_name] = input_value
        # mostly use post method not all
        if method=="post":
            return self.session.post(post_url, data=post_data)  # passing the value to the url
        return self.session.get(post_url,params=post_data) # for the site's which uses get method


    # to discover any vulnerability generically add here
    def run_scanner(self):
        # SSL warning
        # print(Style.BRIGHT + Fore.YELLOW + "[!] Testing SSL certificate..." + Style.RESET_ALL)
        # self.ssl_verify(self, self.target_url)

        for link in self.target_links:
            forms=self.extract_forms(link)
            # adding different form of vulnerability scanner - here XSS, can increase further
            for form in forms:
                print(Style.BRIGHT +  Fore.YELLOW +"[+] Testing form in "+link+Style.RESET_ALL)

                # testing for XSS vulnerability
                is_vulnerable_to_xss=self.test_xss_in_form(form,link)
                if is_vulnerable_to_xss:
                    self.alert_process_XSS()
                    print("\n\n"+Style.BRIGHT +  Fore.RED + Back.WHITE +"-----> XSS discovered in "+link +Style.RESET_ALL)
                    chk=input(Style.BRIGHT +  Fore.CYAN +"[?] Get to know the vulnerable area?[Y/N]" +Style.RESET_ALL)
                    if (chk == "Y" or chk == "y"):
                        print(form) # to print the vulerable site
                    print(Style.BRIGHT +  Fore.GREEN +"\n[+] For safety no further steps being taken."+Style.RESET_ALL)
                    inp = input(Style.BRIGHT +"\n[-] Want to continue testing? [Y/N]"+Style.RESET_ALL)
                    if (inp == "Y" or inp == "y"):
                        continue
                    else:
                        sys.exit(Style.BRIGHT +Fore.WHITE + " -- GOODBYE! -- "+Style.RESET_ALL)

                # testing for SQLi vulnerability
                is_vulnerable_to_sql = self.test_sql_in_form(form, link)
                if is_vulnerable_to_sql:
                    self.alert_process_SQL()
                    print("\n\n"+Style.BRIGHT +  Fore.RED + Back.WHITE +"-----> SQL discovered in " + link +Style.RESET_ALL)
                    chk = input(
                        Style.BRIGHT + Fore.CYAN + "[?] Get to know the vulnerable area?[Y/N]" + Style.RESET_ALL)
                    if (chk == "Y" or chk == "y"):
                        print(form)  # to print the vulerable site
                    print(Style.BRIGHT +  Fore.GREEN +"\n[+] For safety no further steps being taken."+Style.RESET_ALL)
                    inp = input(Style.BRIGHT +"\n[-] Want to continue testing? [Y/N]"+Style.RESET_ALL)
                    if (inp == "Y" or inp=="y"):
                        continue
                    else:
                        sys.exit(Style.BRIGHT +Fore.WHITE +" -- GOODBYE! -- "+Style.RESET_ALL)

            if "=" in link: # means it send data through web application
                print(Style.BRIGHT +  Fore.YELLOW +"[+] Testing " + link+Style.RESET_ALL)
                print(Style.BRIGHT + Fore.BLUE + "[!] Testing SSL certificate..." + Style.RESET_ALL)

                # verfying SSL certificate
                SSL_issue=self.ssl_verify(link)
                if SSL_issue:
                    self.alert_process_SSL()
                    print(Style.BRIGHT +  Fore.GREEN +"\n[+] For safety no further steps being taken."+Style.RESET_ALL)
                    inp = input(Style.BRIGHT + "\n[-] Want to continue testing? [Y/N]" + Style.RESET_ALL)
                    if (inp == "N" or inp == "n"):
                        sys.exit(Style.BRIGHT + Fore.WHITE + " -- GOODBYE! -- " + Style.RESET_ALL)

                # testing for XSS vulnerability
                is_vulnerable_to_xss=self.test_xss_in_link(link)
                if is_vulnerable_to_xss:
                    self.alert_process_XSS()
                    print("\n\n"+Style.BRIGHT +  Fore.RED + Back.WHITE +"-----> Discovered XSS in "+link+Style.RESET_ALL)
                    print(Style.BRIGHT +  Fore.GREEN +"\n[+] For safety no further steps being taken."+Style.RESET_ALL)
                    inp = input(Style.BRIGHT +"\n[-] Want to continue testing? [Y/N]"+Style.RESET_ALL)
                    if (inp == "Y" or inp == "y"):
                        continue
                    else:
                        sys.exit(Style.BRIGHT +Fore.WHITE +" -- GOODBYE! -- "+Style.RESET_ALL)

                # testing for SQLi vulnerability
                is_vulnerable_to_sql = self.test_sql_in_link(link)
                if is_vulnerable_to_sql:
                    self.alert_process_SQL()
                    print("\n\n"+Style.BRIGHT +  Fore.RED + Back.WHITE +"-----> Discovered SQL_injection in " + link+Style.RESET_ALL)
                    print(Style.BRIGHT +  Fore.GREEN +"\n[+] For safety no further steps being taken."+Style.RESET_ALL)
                    inp = input(Style.BRIGHT +"\n[-] Want to continue testing? [Y/N]"+Style.RESET_ALL)
                    if (inp == "Y" or inp == "y"):
                        continue
                    else:
                        sys.exit(Style.BRIGHT +Fore.WHITE +" -- GOODBYE! -- "+Style.RESET_ALL)


    def alert_process_XSS(self):
        for i in (os.popen("ps ax | grep firefox | grep -v grep")):
            field = i.split()
            pid = field[0]
            os.kill(int(pid), signal.SIGKILL)
        webbrowser.open_new_tab("indexXSS.html")

    def alert_process_SQL(self):
        for i in (os.popen("ps ax | grep firefox | grep -v grep")):
            field = i.split()
            pid = field[0]
            os.kill(int(pid), signal.SIGKILL)
        webbrowser.open_new_tab("indexSQL.html")

    def alert_process_SSL(self):
        for i in (os.popen("ps ax | grep firefox | grep -v grep")):
            field = i.split()
            pid = field[0]
            os.kill(int(pid), signal.SIGKILL)
        webbrowser.open_new_tab("indexSSL.html")

####################################################################################################
# SSL VERIFICATION
    # - all kind - wrong host ssl,expired ssl, untrusted root,
    # self signed ssl, revoked ssl, bad pinning
    def ssl_verify(self,link):
        try:
            requests.get(link, verify='/etc/ssl/certs/ca-certificates.crt')
            print(Style.BRIGHT +  Fore.GREEN +"[+] Verified "+Style.RESET_ALL)
            return False
        except requests.exceptions.SSLError as se:
            reason = (str(se).split('"')[1])  # reason-bad handshake
            caused_by = re.search("Caused by [\w]*", str(se)).group()# cause by
            caused = str(re.search("Caused by SSLError[^a-z][\w]*", str(se)).group()).split("(")[1]# cause
            print(Style.BRIGHT + Fore.RED + Back.WHITE +
                  "[-] Insecure Transport (SSL error) vulnerability discovered in: " + link + Style.RESET_ALL)
            print(Fore.BLACK+Back.RED +caused_by)
            print(Fore.BLACK+Back.RED +caused)
            print(Fore.RED +reason)
            return True
        except Exception as e:
            print(Style.RESET_ALL+Fore.CYAN+"[!] Faced some irregular issue. Continuing...")
            return False


# DISCOVERING XSS VULNERABILITIES
    def test_xss_in_form(self,form,url):
        xss_test_script="<sCript>alert('hello')</scriPt>" # changing the capitalization of the code to
        # bypass filters
        response=self.submit_for(form,xss_test_script,url) # submitting form with xss value to the url
        return xss_test_script.encode() in response.content


    # as we can pass the XSS vuln through the link too, not just forms
    def test_xss_in_link(self,url):
        xss_test_script="<sCript>alert('hello')</scriPt>"
        url=url.replace("=","="+xss_test_script)
        response=self.session.get(url)
        return xss_test_script.encode() in response.content

# DISCOVERING SQL VULNERABILITIES in forms and links
# Here any kind of response from the website for the input is being considered as vulnerable
    # as no input validation
# 1=1
# 1 union select user, password from users#
    def test_sql_in_form(self,form,url):
        sql_test_script="1 UniOn Select user, password fRom users#"
        response=self.submit_for(form,sql_test_script,url)
        return sql_test_script.encode() in response.content


    def test_sql_in_link(self,url):
        sql_test_script="1 UniOn Select user, password fRom users#"
        url=url.replace("=","="+sql_test_script)
        response=self.session.get(url)
        return sql_test_script.encode() in response.content
