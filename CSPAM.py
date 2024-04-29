import requests
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import random
import string

def print_banner():
    banner = """
#############################
# AUTHOR: Joel Aviad Ossi
# COMPANY: WebSec BV
# LICENSE: CC BY-SA
# VERSION: v1.0
# WEBSITE: WWW.WEBSEC.NL
#############################
    """
    print(banner)

def get_csp_directives(url):
    """ Fetch headers from URL and extract all CSP directives. """
    try:
        response = requests.get(url)
        csp_header = response.headers.get('Content-Security-Policy')
        if csp_header:
            # Extract all directives from CSP header
            directives = {}
            parts = csp_header.split(';')
            for part in parts:
                if ' ' in part:
                    directive, value = part.strip().split(' ', 1)
                    directives[directive] = value
            return directives
        return {}
    except requests.RequestException as e:
        print(f"Failed to retrieve headers from {url}: {e}")
        return {}

def random_user_agent():
    """ Return a random User-Agent string. """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
        "Mozilla/5.0 (iPad; CPU OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.93 Mobile Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0"
    ]
    return random.choice(user_agents)

def send_report(url, endpoint, directive, value, randomize_domain):
    """ Send a CSP report using an actual directive from the site's policy with a randomized domain. """
    random_domain = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + ".com"
    blocked_uri = f"http://{random_domain}/index.html"

    report_payload = {
        "csp-report": {
            "document-uri": url,
            "referrer": "CSPwn",
            "blocked-uri": blocked_uri,
            "violated-directive": directive + ' ' + value,
            "original-policy": f"{directive} {value}",
        }
    }

    headers = {
        'Content-Type': 'application/json',
        'User-Agent': random_user_agent()
    }

    try:
        response = requests.post(endpoint, data=json.dumps(report_payload), headers=headers)
        if response.status_code in {400, 401, 403, 404, 405, 500}:
            return response.status_code, f"Error encountered: {response.text}"
        return response.status_code, response.text
    except requests.RequestException as e:
        return 0, f"Failed to send CSP report: {e}"

def process_requests(url, randomize_domain):
    directives = get_csp_directives(url)
    if not directives:
        print("No CSP directives found.")
        return

    # Select a random directive to report
    directive, value = random.choice(list(directives.items()))

    # Find endpoint from the directives
    endpoint = directives.get('report-uri', None) or directives.get('report-to', None)
    if not endpoint:
        print("No reporting endpoint found in CSP directives.")
        return

    # Send a report for the selected directive
    status_code, response = send_report(url, endpoint, directive, value, randomize_domain)
    print(f"Report sent for directive '{directive}': Status Code: {status_code}, Response: {response}")

def main():
    print_banner()
    domain = input("Enter the Target Domain (include 'http://' or 'https://'): ").strip()
    randomize_domain = input("Randomize the reported domain name in the CSP report? (Y/N): ").strip().lower() == 'y'
    
    # Normalize and process URL
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain
    domain = urlparse(domain).geturl()

    process_requests(domain, randomize_domain)

if __name__ == "__main__":
    main()
