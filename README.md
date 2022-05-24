# CryWolf

The structure developed is based on a usual website crawler that in general would just be fetching all the hyperlinks and reference to and from that website, on the top of it, a dynamic accessor has been formed to test these links on separate basis for various possible ways of compromises, which can be further appended based on the needs and wants of the user. And taking the suggestion from the [Cranor’s work](https://www.usenix.org/legacy/event/sec09/tech/full_papers/sec09_browser.pdf) the usability ratio of the warning has been tried to improve for better user understanding and keep them away from such malicious weblinks as shown in the figure below.

<img src="crywolf.png">

The scanner executes to firstly validate the SSL certificate of these links prior to any further action. Once the SSL certificate is verified the tests are performed on each of the links and forms on the website, and without any further delay in case of a vulnerable area the alert is sent to the user with a virtually developed method of warning the user, on the side of which the code itself works to take the user to safer platform by both closing the current browser, raising a proper alert formed with keeping usability ratio in mind and allowing user to either learn more about the issue or close the same, while on the other hand if no issues are found user are allowed a proper safe surfing.
<hr>

## Implementation
### Import Libraries
Import the required libraries using `pip3 install [library_name]`

Required libraries-
* scapy
* requests
* bs4
* colorma
* urllib
* re
* webbrowser
* signal

### Changes for testing wanted websites
Can use these websites or as per your need, append the areas in the code as following-
* _**links_to_ignore**_ - in [`Crywolf.py`](CryWolf.py), append the same with the links of websites' logout page URLs.
* **_data_dict_** - in [`Crywolf.py`](CryWolf.py), append or edit with the username and password of the highest and lowset privileged users of the website to perform vulnerability trest at all levels.
* _**vuln_scanner.session.post(site,data)**_ - in [`Crywolf.py`](CryWolf.py), change or append the site with the login page URL of the testing website.
* _**sniff(interface)**_ - in [`Crywolf.py`](CryWolf.py), change interface on which sniffing the packets for URL.

### Adding vulnerability checks
The code currently checks for XSS, SQLi vulnerabilities and SSL certificates. One can add vulnerability checks as per need by adding function in the [scanner code](scanner_python3.py) as -

    def test_vulnerability_in_link(self,url):

        vulnerability_test_script="add_payload_here"

        url=url.replace("=","="+vulnerability_test_script)

        response=self.session.get(url)

        return  vulnerability_test_script.encode() in response.content

    def vulnerability_in_form(self,form,url):

        vulnerability_test_script="payload"

        response=self.submit_for(form,vulnerability_test_script,url)

        return vulnerability_test_script.encode() in response.content

_(The functions and code represented above are just for reference, they might vary as per the vulnerability check performed for.)_



[Reference + Initial Idea](https://www.usenix.org/legacy/event/sec09/tech/full_papers/sec09_browser.pdf)
