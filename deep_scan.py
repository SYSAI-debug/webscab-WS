#!/usr/bin/env python3
import argparse
import requests
import time
import re
import socket
import ssl
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Rich for animated, pretty terminal output.
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# Initialize a Rich Console for styled output
console = Console()

# ---------------------------
# Basic Fetch Function with Retry
# ---------------------------
def fetch_url(url, method='GET', headers=None, retries=3, timeout=5):
    session = requests.Session()
    for attempt in range(1, retries + 1):
        try:
            if method.upper() == 'GET':
                response = session.get(url, headers=headers, timeout=timeout)
            elif method.upper() == 'POST':
                response = session.post(url, headers=headers, timeout=timeout)
            else:
                console.print(f"[bold red]Method {method} not supported.[/bold red]")
                return None
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            console.print(f"[italic yellow]Attempt {attempt} for {url} failed: {e}[/italic yellow]")
            time.sleep(2)
    return None

# ---------------------------
# Asset Extraction from HTML
# ---------------------------
def extract_assets(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    css_files = []
    js_files = []
    php_files = []
    
    # CSS assets via <link rel="stylesheet">
    for link in soup.find_all("link", rel="stylesheet"):
        href = link.get("href")
        if href:
            full_url = urljoin(base_url, href)
            if full_url not in css_files:
                css_files.append(full_url)
    
    # JavaScript assets via <script src="">
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            full_url = urljoin(base_url, src)
            if full_url not in js_files:
                js_files.append(full_url)
    
    # PHP files (heuristic using <a> tags)
    for anchor in soup.find_all("a"):
        href = anchor.get("href")
        if href and ".php" in href.lower():
            full_url = urljoin(base_url, href)
            if full_url not in php_files:
                php_files.append(full_url)
                
    return {"css": css_files, "js": js_files, "php": php_files}

# ---------------------------
# Secret Credential Extraction via Regex
# ---------------------------
def extract_secrets(text):
    secrets_found = {}

    google_api_pattern = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
    google_api_keys = google_api_pattern.findall(text)
    if google_api_keys:
        secrets_found["Google API Keys"] = list(set(google_api_keys))

    generic_key_pattern = re.compile(
        r"(?:api_key|apikey|API_KEY)\s*[:=]\s*[\'\"]?([A-Za-z0-9\-_]{16,50})[\'\"]?"
    )
    generic_keys = generic_key_pattern.findall(text)
    if generic_keys:
        secrets_found["Generic API Keys"] = list(set(generic_keys))

    endpoint_pattern = re.compile(r"(https?://[^\s'\"<>]+api[^\s'\"<>]+)")
    endpoints = endpoint_pattern.findall(text)
    if endpoints:
        secrets_found["API Endpoints"] = list(set(endpoints))

    token_pattern = re.compile(
        r"(?:client_secret|secret|access_token)\s*[:=]\s*[\'\"]?([A-Za-z0-9\-_]{16,100})[\'\"]?"
    )
    tokens = token_pattern.findall(text)
    if tokens:
        secrets_found["Tokens/Secrets"] = list(set(tokens))
        
    return secrets_found

# ---------------------------
# Check Internal Link
# ---------------------------
def is_internal_link(link, domain):
    parsed_link = urlparse(link)
    return parsed_link.netloc == "" or domain in parsed_link.netloc

# ---------------------------
# Recursive Website Crawler
# ---------------------------
def crawl_website(url, max_depth, headers, domain, visited, results):
    if max_depth < 0:
        return

    parsed_url = urlparse(url)
    normalized_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    if normalized_url in visited:
        return

    console.print(f"[italic yellow]Crawling:[/italic yellow] [bold]{normalized_url}[/bold] (depth: {max_depth})")
    visited.add(normalized_url)
    
    response = fetch_url(normalized_url, headers=headers)
    if response is None:
        return

    html = response.text
    assets = extract_assets(html, normalized_url)
    secrets = extract_secrets(html)

    results[normalized_url] = {
        "assets": assets,
        "secrets": secrets,
        "links": []
    }
    
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.find_all("a"):
        href = anchor.get("href")
        if href:
            full_url = urljoin(normalized_url, href)
            parsed_full_url = urlparse(full_url)
            full_url = parsed_full_url.scheme + "://" + parsed_full_url.netloc + parsed_full_url.path
            if is_internal_link(full_url, domain):
                if full_url not in visited:
                    results[normalized_url]["links"].append(full_url)
                    crawl_website(full_url, max_depth - 1, headers, domain, visited, results)

# ---------------------------
# Common Exposed Files Scan
# ---------------------------
def scan_common_files(base_url, headers):
    common_paths = [".env", "config.php", "config.php.bak", "robots.txt", "sitemap.xml", ".git/config"]
    found_files = {}
    for path in common_paths:
        target_url = urljoin(base_url, path)
        response = fetch_url(target_url, headers=headers)
        if response and response.status_code == 200:
            found_files[path] = response.text[:200]
    return found_files

# ---------------------------
# Advanced Code Analysis: Display source with syntax highlighting
# ---------------------------
def display_file_with_colors(url, file_extension):
    console.print(f"\n[bold blue]--- Advanced Code Analysis for {url} ---[/bold blue]")
    response = fetch_url(url)
    if response:
        content = response.text
        try:
            from pygments import highlight
            from pygments.lexers import get_lexer_by_name, guess_lexer_for_filename
            from pygments.formatters import TerminalFormatter

            if file_extension.lower() == "css":
                lexer = get_lexer_by_name("css")
            elif file_extension.lower() == "php":
                lexer = get_lexer_by_name("php")
            elif file_extension.lower() == "js":
                lexer = get_lexer_by_name("javascript")
            elif file_extension.lower() in ("html", "htm", "hml"):
                lexer = get_lexer_by_name("html")
            elif file_extension.lower() == "tsx":
                lexer = get_lexer_by_name("typescript")
            else:
                lexer = guess_lexer_for_filename(url, content)

            colored_code = highlight(content, lexer, TerminalFormatter())
            console.print(colored_code)
        except ImportError:
            console.print("[red]Pygments not installed. Showing plain text output:[/red]")
            console.print(content)
    else:
        console.print(f"[red]Failed to fetch the file: {url}[/red]")

# ---------------------------
# File Type Detection via Extension
# ---------------------------
def detect_file_root_class(url):
    parsed = urlparse(url)
    path = parsed.path
    if '.' in path:
        ext = path.split('.')[-1].lower()
        mapping = {
            "css": "Cascading Style Sheet",
            "php": "PHP Script",
            "html": "HTML Document",
            "htm": "HTML Document",
            "hml": "Possibly HTML Document",
            "js": "JavaScript",
            "tsx": "TypeScript with JSX",
        }
        return mapping.get(ext, f"Unknown file type: .{ext}")
    return "No file extension detected"

# ---------------------------
# Determine Page Status for Summary Table
# ---------------------------
def get_page_status(data):
    if data["secrets"]:
        return "Bad"       # Will show in green (bad secrets)
    elif any(data["assets"].values()):
        return "Neutral"   # Shows in yellow if assets exist, but no secrets
    else:
        return "Good"      # Shown in red if clean

status_color_mapping = {
    "Good": "red",
    "Neutral": "yellow",
    "Bad": "green"
}

# ---------------------------
# HTTP Header & SSL/TLS Analysis
# ---------------------------
def analyze_http_headers(url, headers):
    response = fetch_url(url, headers=headers)
    if response:
        return response.headers
    return {}

def analyze_ssl_certificate(url):
    if not url.startswith("https://"):
        return "Non-SSL connection"
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port if parsed.port else 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        return f"SSL certificate analysis failed: {e}"
    if cert:
        notAfter = cert.get('notAfter', 'N/A')
        issuer = cert.get('issuer', 'N/A')
        return f"Issuer: {issuer}, Expires: {notAfter}"
    return "No certificate found."

# ---------------------------
# CMS/Framework Fingerprinting
# ---------------------------
def fingerprint_cms(html):
    cms = []
    if "wp-content" in html.lower() or "wordpress" in html.lower():
        cms.append("WordPress")
    if "Joomla" in html:
        cms.append("Joomla")
    if "Drupal" in html:
        cms.append("Drupal")
    soup = BeautifulSoup(html, "html.parser")
    meta_tag = soup.find("meta", attrs={"name": "generator"})
    if meta_tag:
        content = meta_tag.get("content", "").lower()
        if "wordpress" in content and "WordPress" not in cms:
            cms.append("WordPress")
        elif "joomla" in content and "Joomla" not in cms:
            cms.append("Joomla")
        elif "drupal" in content and "Drupal" not in cms:
            cms.append("Drupal")
    return cms

# ---------------------------
# Vulnerability & Exploit Scanning (Simple Check)
# ---------------------------
def vulnerability_scan(html):
    vulnerabilities = []
    match = re.search(r"jquery[-\.]?(\d+\.\d+\.\d+)", html, re.IGNORECASE)
    if match:
        version = match.group(1)
        if version.startswith("1."):
            vulnerabilities.append(f"Old jQuery version detected: {version}")
    return vulnerabilities

# ---------------------------
# SEO Analysis
# ---------------------------
def analyze_seo(html):
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string if soup.title else "No title"
    meta_desc_tag = soup.find("meta", {"name": "description"})
    meta_desc = meta_desc_tag.get("content", "No meta description") if meta_desc_tag else "No meta description"
    h1_tags = [h.get_text(strip=True) for h in soup.find_all("h1")]
    return {"title": title, "meta_description": meta_desc, "h1_tags": h1_tags}

# ---------------------------
# Malicious Content & Phishing Detection
# ---------------------------
def detect_malicious_content(html):
    soup = BeautifulSoup(html, "html.parser")
    warnings = []
    iframes = soup.find_all("iframe")
    for iframe in iframes:
        style = iframe.get("style", "")
        if "display:none" in style.lower():
            warnings.append("Hidden iframe detected.")
    scripts = soup.find_all("script")
    for script in scripts:
        if script.string and "eval(" in script.string:
            warnings.append("Potential use of eval() detected in script.")
    return warnings

# ---------------------------
# Directory Bruteforcing / File Enumeration
# ---------------------------
def directory_bruteforce(base_url, headers):
    common_dirs = ["admin", "backup", "test", "old", "login", "uploads", "data"]
    found_dirs = {}
    for d in common_dirs:
        dir_url = urljoin(base_url + "/", d + "/")
        resp = fetch_url(dir_url, headers=headers)
        if resp and resp.status_code == 200:
            found_dirs[d] = "Exists"
        else:
            found_dirs[d] = "Not found"
    return found_dirs

# ---------------------------
# MAIN FUNCTION: Orchestrate Crawling & Advanced Scanning
# ---------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Deep Domain Scanner with Advanced Modules: Crawl a domain for assets, secrets, HTTP/SSL, CMS fingerprinting, port scanning, vulnerability checks, SEO analysis, malicious content detection, and directory brute forcing."
    )
    parser.add_argument("url", help="Base URL to crawl (e.g., https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (e.g., 'User-Agent: my-agent')")
    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            try:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
            except ValueError:
                console.print(f"[red]Invalid header format: {h}[/red]")
    
    parsed_domain = urlparse(args.url).netloc
    domain = parsed_domain

    visited = set()
    results = {}

    with console.status("[bold green]Scanning domain... Please wait[/bold green]", spinner="bouncingBall"):
        crawl_website(args.url, args.depth, headers, domain, visited, results)
    
    # ---------------------------
    # Display Crawl Summary Table
    # ---------------------------
    table = Table(title="Crawl Summary", box=box.DOUBLE_EDGE)
    table.add_column("Page", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Assets", justify="center")
    table.add_column("Secrets", justify="center")
    table.add_column("Links", justify="center")
    for page, data in results.items():
        status = get_page_status(data)
        color = status_color_mapping.get(status, "white")
        assets_count = sum([len(lst) for lst in data["assets"].values()])
        secrets_count = sum([len(lst) for lst in data["secrets"].values()])
        links_count = len(data["links"])
        table.add_row(
            page,
            f"[{color}]{status}[/{color}]",
            str(assets_count),
            str(secrets_count),
            str(links_count)
        )
    console.print(table)
    
    # ---------------------------
    # Display Common Exposed Files
    # ---------------------------
    console.print("\n[bold underline blue]Common Exposed Files on Base Domain[/bold underline blue]")
    common_files = scan_common_files(args.url, headers)
    if common_files:
        for file, content in common_files.items():
            console.print(f"[magenta]{file}:[/magenta] {content}\n")
    else:
        console.print("[italic]No common files found or access denied.[/italic]")

    # ---------------------------
    # Advanced Analysis: HTTP Headers & SSL/TLS Certificate
    # ---------------------------
    console.print("\n[bold underline blue]HTTP Header & SSL/TLS Analysis[/bold underline blue]")
    headers_data = analyze_http_headers(args.url, headers)
    if headers_data:
        table_headers = Table(title="HTTP Headers", box=box.SIMPLE)
        table_headers.add_column("Header", style="cyan", no_wrap=True)
        table_headers.add_column("Value", style="magenta")
        for k, v in headers_data.items():
            table_headers.add_row(k, str(v))
        console.print(table_headers)
    else:
        console.print("[red]No headers obtained.[/red]")
    
    ssl_info = analyze_ssl_certificate(args.url)
    console.print(f"\n[bold underline blue]SSL/TLS Certificate Analysis:[/bold underline blue] {ssl_info}")

    # ---------------------------
    # Advanced Analysis: CMS Fingerprinting, Vulnerability & SEO Analysis, Malicious Content Detection
    # ---------------------------
    base_response = fetch_url(args.url, headers=headers)
    if base_response:
        base_html = base_response.text
        cms_fingerprints = fingerprint_cms(base_html)
        if cms_fingerprints:
            console.print(f"\n[bold underline blue]Detected CMS/Framework:[/bold underline blue] {', '.join(cms_fingerprints)}")
        else:
            console.print("[italic]No CMS fingerprints detected.[/italic]")
        
        vulnerability_issues = vulnerability_scan(base_html)
        if vulnerability_issues:
            console.print("\n[bold underline blue]Vulnerability Issues Detected:[/bold underline blue]")
            for issue in vulnerability_issues:
                console.print(f"[red]{issue}[/red]")
        else:
            console.print("\n[bold green]No obvious vulnerability issues detected.[/bold green]")
        
        seo_data = analyze_seo(base_html)
        seo_table = Table(title="SEO Analysis", box=box.SIMPLE)
        seo_table.add_column("Property", style="cyan")
        seo_table.add_column("Value", style="magenta")
        seo_table.add_row("Title", seo_data.get("title", "N/A"))
        seo_table.add_row("Meta Description", seo_data.get("meta_description", "N/A"))
        seo_table.add_row("H1 Tags", ", ".join(seo_data.get("h1_tags", [])))
        console.print("\n")
        console.print(seo_table)
        
        malicious_warnings = detect_malicious_content(base_html)
        if malicious_warnings:
            console.print("\n[bold underline red]Malicious Content Warnings:[/bold underline red]")
            for warn in malicious_warnings:
                console.print(f"[red]{warn}[/red]")
        else:
            console.print("\n[bold green]No malicious content detected.[/bold green]")
        
    # ---------------------------
    # Advanced Analysis: Port Scanning
    # ---------------------------
    ports = port_scan(domain)
    port_table = Table(title="Port Scanning Results", box=box.SIMPLE)
    port_table.add_column("Port", style="cyan", no_wrap=True)
    port_table.add_column("Status", style="magenta")
    for p, status in ports.items():
        port_table.add_row(str(p), str(status))
    console.print("\n")
    console.print(port_table)
    
    # ---------------------------
    # Advanced Analysis: Directory Bruteforcing
    # ---------------------------
    dir_results = directory_bruteforce(args.url, headers)
    dir_table = Table(title="Directory Bruteforcing Results", box=box.SIMPLE)
    dir_table.add_column("Directory", style="cyan", no_wrap=True)
    dir_table.add_column("Status", style="magenta")
    for d, result in dir_results.items():
        dir_table.add_row(d, result)
    console.print("\n")
    console.print(dir_table)
    
    # ---------------------------
    # Advanced Code Analysis: For each detected asset, show file type and source with syntax highlighting.
    # ---------------------------
    console.print("\n[bold underline blue]Advanced Code Analysis for Detected Assets[/bold underline blue]")
    for page, data in results.items():
        assets = data.get("assets", {})
        for asset_type, assets_list in assets.items():
            for asset_url in assets_list:
                parts = asset_url.rsplit(".", 1)
                if len(parts) == 2:
                    ext = parts[1].split('?')[0]
                    file_class = detect_file_root_class(asset_url)
                    console.print(f"[bold]{asset_url}[/bold] - Detected as: [italic]{file_class}[/italic]")
                    if ext.lower() in ['css', 'php', 'js', 'html', 'htm', 'hml', 'tsx']:
                        display_file_with_colors(asset_url, ext)

    console.print("\n[bold green]Scanning complete![/bold green]")

if __name__ == "__main__":
    main()
