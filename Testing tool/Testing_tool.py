import requests
import re
import urllib.parse
import argparse
from termcolor import colored

# List of common field names for username, password, and submit button
possible_usernames = ["username", "user", "email", "login", "name"]
possible_passwords = ["password", "pass", "pwd"]
possible_submit_buttons = ["submit", "Login", "log in", "signin"]


class Scanner:
    def __init__(self, url, ignore_links):
        # Open a session to maintain progress, especially if we need to log in before reaching the URL.
        self.session = requests.Session()
        # self.session.headers.update({'Cookie': 'shabkni_session=eyJpdiI6ImtNejZjSGQ4QlM4N2paT1JXV0lHcFE9PSIsInZhbHVlIjoiRlV3SDdVRVlHZ1RvUFNJTEdJbVFNR3Q3UVBydjZGSWxrMFROWDFyQ21OK0VjQ1grQkdkNlg4MVoxeDc3anlSbzZlanVaT1prZW95b3dHRW1aODV6YWt6UTdoZ2dkQ0NpYkVRUHNISTdmV1dXTW1XYXdGSHM0dmNKTllZTXJxYmciLCJtYWMiOiI3N2M1MDZlYzQ3MDM5Yzc4Y2M2NmU3YzEzMDE4NDY2ODQ5OTIxYjdlMDQzOTBmNWEyMDE1MDMyNzJlNDZlOTc5IiwidGFnIjoiIn0', })
        self.target_url = url
        self.target_links = []
        self.links_to_ignore = ignore_links
        

    def extract_links(self, url):
        # Get all possible links from an HTML page, possible links are found after the "href" tag.
        response = self.session.get(url)
        return re.findall('(?:href=")(.*?)"', str(response.content))

    def crawl(self, url=None):
        if url is None:
            url = self.target_url
        # print(f"[DEBUG] Starting crawl on {url}")
        href_links = self.extract_links(url)
        for link in href_links:
            # Link links using the actual URL (because the link after the href tag is not the full URL)
            link = urllib.parse.urljoin(url, link)
            if "#" in link:
                link = link.split("#")[0]
                # Debug: Show each link being processed
                # print(f"[DEBUG] Found link with #: {link}")
            # Filter out non-HTML assets
            if any(link.endswith(ext) for ext in [".ico", ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg"]):
                # print(f"[DEBUG] Skipping non-HTML asset: {link}")
                continue
            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)
                print(colored("Link Found: " + str(link), 'cyan'))
                self.crawl(url)

    def save_report(self, filename="links.txt"):
        with open(filename, 'w') as file:
            for links in self.target_links:
                file.write(links+"\n")
        print(colored(f"[+] Report saved to {filename}",'green'))

    def try_login(self, login_url, username, password):
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
        print(colored("[-] All login attempts failed. Please check your credentials and field names.", 'light_red',
                      attrs=['blink']))
        return False


def get_arguments():
    parser = argparse.ArgumentParser(description=colored("This is a URL crowler to get all possible linkes from a specific URL",'magenta'))
    parser.add_argument("-u", "--urls", required=True, help="Target URLs to scan, separated by commas")
    parser.add_argument("-i", "--ignore", help="Links to ignore, separated by commas")
    parser.add_argument("-l", "--login_url", help="Login URL if authentication is required")
    parser.add_argument("-n", "--username", help="Username for login")
    parser.add_argument("-p", "--password", help="Password for login")
    parser.add_argument("-c", "--cookies", help="set specific session by sending the session cookies")
    return parser.parse_args()


def parse_cookies(cookie_str):
    cookies = {}
    for cookie in cookie_str.split(";"):
        name, value = cookie.strip().split("=", 1)
        cookies[name] = value
    return cookies


def get_seed_urls(options):
    # Split the target URLs by comma to handle multiple URLs or a single URL
    urls = options.urls.split(",")
    return [url.strip() for url in urls]  # Remove any leading/trailing whitespace


def main():
    options = get_arguments()
    target_url = options.urls
    links_to_ignore = options.ignore.split(",") if options.ignore else []
    seed_urls = get_seed_urls(options)
    login_url = options.login_url
    username = options.username
    password = options.password
    cookies = options.cookies
    scanner = Scanner(target_url, links_to_ignore)
    if login_url:
        scanner.try_login(login_url, username, password)
    if cookies:
        scanner.session.cookies.update(parse_cookies(cookies))
    for url in seed_urls:
        # print(f"[DEBUG] Starting scan on: {url}")
        scanner.target_url = url
        scanner.target_links = [url]  # Reset target links for each new URL
        scanner.crawl()

    # Save report after all URLs are scanned
    scanner.save_report()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Ctrl+C detected, stopping the scan...", 'yellow', attrs=['blink']))
    except Exception as e:
        print(colored("[-] " + str(e), 'red', attrs=['bold']))
        