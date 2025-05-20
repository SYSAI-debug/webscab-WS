#!/usr/bin/env python3
import argparse
import requests
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def fetch_url(url, method='GET', headers=None, retries=3, timeout=5):
    session = requests.Session()
    for attempt in range(1, retries + 1):
        try:
            if method.upper() == 'GET':
                response = session.get(url, headers=headers, timeout=timeout)
            elif method.upper() == 'POST':
                response = session.post(url, headers=headers, timeout=timeout)
            else:
                print("Method not supported.")
                return None
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            print(f"Attempt {attempt} failed: {e}")
            time.sleep(2)  # You might implement exponential backoff here.
    return None

def extract_assets(html, base_url):
    """
    Extract external assets like CSS, JavaScript, and PHP file links from HTML content.
    """
    soup = BeautifulSoup(html, "html.parser")
    css_files = []
    js_files = []
    php_files = []
    
    # Extract CSS files from <link rel="stylesheet">
    for link in soup.find_all("link", rel="stylesheet"):
        href = link.get("href")
        if href:
            full_url = urljoin(base_url, href)
            if full_url not in css_files:
                css_files.append(full_url)
                
    # Extract JavaScript files from <script src="">
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            full_url = urljoin(base_url, src)
            if full_url not in js_files:
                js_files.append(full_url)
    
    # Extract PHP file links by checking <a> tags for '.php'
    for anchor in soup.find_all("a"):
        href = anchor.get("href")
        if href and ".php" in href.lower():
            full_url = urljoin(base_url, href)
            if full_url not in php_files:
                php_files.append(full_url)
                
    return css_files, js_files, php_files

def extract_secrets(text):
    """
    Scan the given text for potential secret credentials.
    
    The following regex patterns are used:
      - Google API Keys (typically starting with "AIza")
      - Generic API keys indicated by variable names like api_key or apikey
      - Potential API endpoints (URLs containing 'api')
      - Generic tokens, secrets, or access tokens
    """
    secrets_found = {}

    # Pattern for Google API keys
    google_api_pattern = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
    google_api_keys = google_api_pattern.findall(text)
    if google_api_keys:
        secrets_found["Google API Keys"] = list(set(google_api_keys))

    # Generic API key detection, for variables like api_key, apikey, or API_KEY
    generic_key_pattern = re.compile(
        r"(?:api_key|apikey|API_KEY)\s*[:=]\s*[\'\"]?([A-Za-z0-9\-_]{16,50})[\'\"]?"
    )
    generic_keys = generic_key_pattern.findall(text)
    if generic_keys:
        secrets_found["Generic API Keys"] = list(set(generic_keys))

    # Look for endpoint URLs that include 'api'
    endpoint_pattern = re.compile(r"(https?://[^\s'\"<>]+api[^\s'\"<>]+)")
    endpoints = endpoint_pattern.findall(text)
    if endpoints:
        secrets_found["API Endpoints"] = list(set(endpoints))

    # Detect tokens and secrets variables such as client_secret, secret, or access_token
    token_pattern = re.compile(
        r"(?:client_secret|secret|access_token)\s*[:=]\s*[\'\"]?([A-Za-z0-9\-_]{16,100})[\'\"]?"
    )
    tokens = token_pattern.findall(text)
    if tokens:
        secrets_found["Tokens/Secrets"] = list(set(tokens))
        
    return secrets_found

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Python Curl Script with Asset & Credential Detection"
    )
    parser.add_argument("url", help="URL to fetch")
    parser.add_argument("-m", "--method", default="GET",
                        help="HTTP method (GET, POST, etc.)")
    parser.add_argument("-H", "--header", action="append",
                        help="Custom headers (e.g., 'User-Agent: my-agent')")
    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            try:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
            except ValueError:
                print(f"Invalid header format: {h}")
    
    response = fetch_url(args.url, method=args.method, headers=headers)
    if response:
        content_type = response.headers.get("Content-Type", "")
        if "html" in content_type:
            # Parse and prettify HTML
            soup = BeautifulSoup(response.text, "html.parser")
            print("----- Page Content (Prettified HTML) -----")
            print(soup.prettify())
            
            # Extract linked assets
            css_files, js_files, php_files = extract_assets(response.text, args.url)
            if css_files:
                print("\n----- Detected CSS Files -----")
                for css in css_files:
                    print(css)
            if js_files:
                print("\n----- Detected JavaScript Files -----")
                for js in js_files:
                    print(js)
            if php_files:
                print("\n----- Detected PHP Files -----")
                for php in php_files:
                    print(php)
            
            # Extract potential secret credentials from HTML content
            secrets = extract_secrets(response.text)
            if secrets:
                print("\n----- Detected Secret Credentials -----")
                for category, items in secrets.items():
                    print(f"{category}:")
                    for item in items:
                        print("  ", item)
        elif "json" in content_type:
            import json
            print(json.dumps(response.json(), indent=4))
        else:
            print(response.text)
    else:
        print("Failed to complete the request.")

if __name__ == "__main__":
    main()
