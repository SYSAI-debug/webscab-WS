#!/usr/bin/env python3
import argparse
import requests
import time
import re
import socket
import ssl
import sqlite3
import json
import random
import sys
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Rich for animated styled terminal output.
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# Initialize Rich Console.
console = Console()


# ---------------------------
# NOTICE MESSAGE (Wscab disclaimer)
# ---------------------------
def print_startup_notice():
    console.print("\n[bold red]NOTICE:[/bold red] By starting Wscab (Web Scab), you acknowledge that we may investigate the use of this tool if it is used in an unethical manner.")
    console.print("Please review the usage policy at [underline]www.jconi.software/use[/underline].\n")


# ---------------------------
# LIVE DEVELOPER LOCATION DISPLAY
# ---------------------------
def print_live_developer_location():
    # Hard-coded live development location.
    developer_location = "Kampala, Uganda"
    console.print("[bold cyan]Live Developed Loc: is [underline]" + developer_location + "[/underline][/bold cyan]\n")


# ---------------------------
# Pre-Tool Prompt Options
# ---------------------------
def prompt_options():
    console.print("Choose an option:")
    console.print("  [bold yellow]y[/bold yellow] - Start the tool")
    console.print("  [bold yellow]n[/bold yellow] - Exit the tool")
    console.print("  [bold yellow]d[/bold yellow] - Debug Matrix (simulate matrix effect and deny service)")
    choice = input("Enter option (y/n/d): ").strip().lower()
    if choice == "y":
        return True
    elif choice == "n":
        exit_with_bye()
    elif choice == "d":
        run_matrix_animation()
    else:
        console.print("[red]Invalid option. Exiting.[/red]")
        sys.exit(1)


# ---------------------------
# Exit with Animated Bye-Bye Message
# ---------------------------
def exit_with_bye():
    bye_message = "Bye-Bye"
    console.print("\n", end="")
    for char in bye_message:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.3)
    sys.stdout.write("\n")
    sys.exit(0)


# ---------------------------
# Matrix Animation then Deny Service
# ---------------------------
def run_matrix_animation():
    console.print("[bold green]Starting matrix effect...[/bold green]")
    start_time = time.time()
    while time.time() - start_time < 3:
        line = ''.join(random.choice("01") for _ in range(80))
        console.print(line, style="green")
        time.sleep(0.05)
    console.print("[bold red]Service Denied[/bold red]")
    sys.exit(0)


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
# Extract Assets from HTML
# ---------------------------
def extract_assets(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    css_files = []
    js_files = []
    php_files = []

    # Extract CSS assets.
    for link in soup.find_all("link", rel="stylesheet"):
        href = link.get("href")
        if href:
            full_url = urljoin(base_url, href)
            if full_url not in css_files:
                css_files.append(full_url)

    # Extract JavaScript assets.
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            full_url = urljoin(base_url, src)
            if full_url not in js_files:
                js_files.append(full_url)

    # Extract PHP files (heuristic using <a> tags).
    for anchor in soup.find_all("a"):
        href = anchor.get("href")
        if href and ".php" in href.lower():
            full_url = urljoin(base_url, href)
            if full_url not in php_files:
                php_files.append(full_url)

    return {"css": css_files, "js": js_files, "php": php_files}


# ---------------------------
# Extract Secrets via Regex
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
# Check for Internal Links
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
        "links": [],
        "static_warnings": []  # Populated later via static analysis
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
# Scan for Common Exposed Files
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
# Advanced Code Analysis (syntax highlighting)
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
# Detect File Type via Extension
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
        return "Bad"       # High risk: secrets detected
    elif any(data["assets"].values()):
        return "Neutral"   # Assets found but no overt secrets
    else:
        return "Good"      # Minimal risk
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
# Advanced Vulnerability & Static Code Analysis
# ---------------------------
def static_code_analysis(content, file_type):
    warnings = []
    # Check for usage of eval() in PHP/JS files.
    if file_type in ["php", "js"]:
        if "eval(" in content:
            warnings.append("Usage of eval() detected – may lead to code injection.")
    # Check for possible hard-coded credentials.
    if re.search(r"['\"](AKIA|AIza)[A-Za-z0-9\-_]{20,50}['\"]", content):
        warnings.append("Possible hard-coded credential detected.")
    return warnings


# ---------------------------
# Advanced Misconfiguration Lookup
# ---------------------------
def lookup_misconfigurations(headers):
    misconfigs = []
    required_headers = {
        "Strict-Transport-Security": "Enforces secure communication.",
        "Content-Security-Policy": "Helps mitigate XSS attacks.",
        "X-Frame-Options": "Prevents clickjacking.",
        "X-Content-Type-Options": "Prevents MIME type sniffing."
    }
    for header, description in required_headers.items():
        if header not in headers:
            misconfigs.append(f"Missing {header}: {description}")
    return misconfigs


# ---------------------------
# Behavioral & Heuristic Analysis
# ---------------------------
def heuristic_analysis(results, misconfigs):
    score = 0
    details = []

    for page, data in results.items():
        if data["secrets"]:
            score += 2
            details.append(f"{page}: Secrets found (+2)")
        if data.get("static_warnings"):
            count = len(data["static_warnings"])
            score += 3 * count
            details.append(f"{page}: {count} static code warnings (+{3 * count})")
        if data["assets"] and not data["secrets"]:
            score += 1
            details.append(f"{page}: Assets present, no secrets (+1)")

    misconfig_count = len(misconfigs)
    score += misconfig_count
    if misconfig_count:
        details.append(f"Misconfigurations: {misconfig_count} issues (+{misconfig_count})")

    if score >= 10:
        risk = "High"
    elif score >= 5:
        risk = "Medium"
    else:
        risk = "Low"

    return {"score": score, "risk": risk, "details": details}


# ---------------------------
# Intelligence Threat Scanning (local heuristic)
# ---------------------------
def intelligence_threat_scan(results):
    threat_items = []
    for page, data in results.items():
        risk = 0
        risk += 3 * sum(len(lst) for lst in data["secrets"].values())
        risk += 2 * len(data.get("static_warnings", []))
        if risk >= 5:
            threat_items.append((page, risk))
    return threat_items


# ---------------------------
# Persistent Storage & Reporting
# ---------------------------
def store_results_to_db(results, db_filename='scan_results.db'):
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            page TEXT PRIMARY KEY,
            assets TEXT,
            secrets TEXT,
            links TEXT,
            static_warnings TEXT,
            scan_time TEXT
        )
    ''')
    scan_time = datetime.utcnow().isoformat()
    for page, data in results.items():
        cursor.execute('''
            INSERT OR REPLACE INTO scan_results (page, assets, secrets, links, static_warnings, scan_time)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            page,
            json.dumps(data["assets"]),
            json.dumps(data["secrets"]),
            json.dumps(data["links"]),
            json.dumps(data.get("static_warnings", [])),
            scan_time
        ))
    conn.commit()
    conn.close()


def generate_html_report(db_filename='scan_results.db', output_file='report.html'):
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_results")
    rows = cursor.fetchall()
    conn.close()

    html = """
    <html>
      <head>
        <title>Security Audit Report</title>
        <style>
          body { font-family: Arial, sans-serif; }
          table { border-collapse: collapse; width: 100%; }
          th, td { border: 1px solid #ddd; padding: 8px; }
          th { background-color: #f2f2f2; }
          tr:hover { background-color: #f5f5f5; }
        </style>
      </head>
      <body>
        <h2>Security Audit Report</h2>
        <table>
          <tr>
            <th>Page</th>
            <th>Assets</th>
            <th>Secrets</th>
            <th>Links</th>
            <th>Static Warnings</th>
            <th>Scan Time</th>
          </tr>
    """
    for row in rows:
        html += "<tr>"
        for cell in row:
            html += f"<td>{cell}</td>"
        html += "</tr>"
    html += """
        </table>
      </body>
    </html>
    """
    with open(output_file, "w") as f:
        f.write(html)
    console.print(f"[bold green]HTML Report generated: {output_file}[/bold green]")


# ---------------------------
# MAIN FUNCTION: Orchestrate the Complete Audit
# ---------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Wscab (Web Scab) – Deep Domain Scanner & Security Audit Tool. Use responsibly!"
    )
    parser.add_argument("url", help="Base URL to crawl (e.g., https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (e.g., 'User-Agent: my-agent')")
    args = parser.parse_args()

    # Print startup notice and live developer location.
    print_startup_notice()
    print_live_developer_location()

    # Prompt for user option.
    if not prompt_options():
        sys.exit(0)

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

    # For each detected asset, perform static code analysis.
    for page, data in results.items():
        for asset_type, assets_list in data["assets"].items():
            for asset_url in assets_list:
                parts = asset_url.rsplit(".", 1)
                if len(parts) == 2:
                    ext = parts[1].split('?')[0]
                    response = fetch_url(asset_url)
                    if response:
                        content = response.text
                        warnings = static_code_analysis(content, ext)
                        if warnings:
                            data.setdefault("static_warnings", []).extend(warnings)

    # Display summary table.
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

    # Scan for common exposed files.
    console.print("\n[bold underline blue]Common Exposed Files on Base Domain[/bold underline blue]")
    common_files = scan_common_files(args.url, headers)
    if common_files:
        for file, content in common_files.items():
            console.print(f"[magenta]{file}:[/magenta] {content}\n")
    else:
        console.print("[italic]No common files found or access denied.[/italic]")

    # Advanced Analysis: HTTP Headers & SSL/TLS.
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

    # Advanced Analysis: CMS Fingerprinting, Vulnerability Scan, SEO, Malicious Content.
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

    # Advanced Analysis: Directory Bruteforcing.
    dir_results = directory_bruteforce(args.url, headers)
    dir_table = Table(title="Directory Bruteforcing Results", box=box.SIMPLE)
    dir_table.add_column("Directory", style="cyan", no_wrap=True)
    dir_table.add_column("Status", style="magenta")
    for d, result in dir_results.items():
        dir_table.add_row(d, result)
    console.print("\n")
    console.print(dir_table)

    # Advanced Code Analysis for Detected Assets.
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

    # Advanced Misconfiguration Lookup.
    misconfigs = lookup_misconfigurations(headers_data)
    console.print("\n[bold underline blue]Misconfiguration Lookup[/bold underline blue]")
    if misconfigs:
        for m in misconfigs:
            console.print(f"[red]{m}[/red]")
    else:
        console.print("[bold green]No misconfigurations detected.[/bold green]")

    # Behavioral / Heuristic Analysis.
    heuristic = heuristic_analysis(results, misconfigs)
    console.print("\n[bold underline blue]Behavioral and Heuristic Analysis[/bold underline blue]")
    console.print(f"Overall Risk Score: {heuristic['score']} => [bold]{heuristic['risk']} Risk[/bold]")
    for detail in heuristic["details"]:
        console.print(f"- {detail}")

    # Intelligence Threat Scanning (local heuristics).
    threat_items = intelligence_threat_scan(results)
    console.print("\n[bold underline blue]Intelligence Threat Scan Results[/bold underline blue]")
    if threat_items:
        threat_table = Table(title="Threat Intelligence", box=box.SIMPLE)
        threat_table.add_column("Page", style="cyan", no_wrap=True)
        threat_table.add_column("Risk Score", style="magenta")
        for page, risk in threat_items:
            threat_table.add_row(page, str(risk))
        console.print(threat_table)
    else:
        console.print("[bold green]No intelligence-based threats detected.[/bold green]")

    # Persistent Storage & Reporting.
    store_results_to_db(results, db_filename="scan_results.db")
    generate_html_report(db_filename="scan_results.db", output_file="report.html")

    # Final note for users.
    console.print("\n[bold cyan]Wscab (Web Scab) was developed by a rich community. Any concerns? Visit [underline]www.jconi.software[/underline].[/bold cyan]")


if __name__ == "__main__":
    main()
