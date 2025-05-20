#!/usr/bin/env python3
import argparse
import requests
import sys
import json
import time
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich import box

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced Curl Python Script: Make HTTP requests with enhanced output."
    )
    parser.add_argument("url", help="URL to request")
    parser.add_argument(
        "--method", "-X",
        default="GET",
        choices=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        help="HTTP method (default: GET)"
    )
    parser.add_argument(
        "--data", "-d",
        help="Data to send with the request (raw string or JSON if Content-Type is application/json)"
    )
    parser.add_argument(
        "--header", "-H",
        action="append",
        help="Custom header, e.g. -H 'Content-Type: application/json'. Can be used multiple times."
    )
    parser.add_argument(
        "--proxy", "-p",
        help="Proxy to use, e.g. http://127.0.0.1:8080"
    )
    parser.add_argument(
        "--insecure", "-k",
        action="store_true",
        help="Allow insecure SSL connections (don’t verify server certificate)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        help="Timeout for the request in seconds (default: 10)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args()

def build_headers(header_list):
    headers = {}
    if header_list:
        for h in header_list:
            if ':' in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers

def main():
    args = parse_arguments()
    console = Console()
    
    method = args.method.upper()
    url = args.url
    headers = build_headers(args.header)
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    # Prepare request parameters.
    req_kwargs = {
        "url": url,
        "method": method,
        "headers": headers,
        "timeout": args.timeout,
        "verify": not args.insecure,
        "proxies": proxies,
    }
    
    # If there's data, try to send it either as JSON (if the header is set) or as raw data.
    if args.data:
        if headers.get("Content-Type", "").lower() == "application/json":
            try:
                req_kwargs["json"] = json.loads(args.data)
            except json.JSONDecodeError:
                console.print("[red]Error: The provided data is not valid JSON.[/red]")
                sys.exit(1)
        else:
            req_kwargs["data"] = args.data

    if args.verbose:
        console.print("[bold blue]Request Details:[/bold blue]")
        console.print(f"  URL: {url}")
        console.print(f"  Method: {method}")
        console.print(f"  Headers: {headers}")
        if args.data:
            console.print(f"  Data: {args.data}")
        if proxies:
            console.print(f"  Proxies: {proxies}")
        console.print(f"  Verify SSL: {not args.insecure}")
        console.print(f"  Timeout: {args.timeout} seconds\n")

    start_time = time.time()
    try:
        response = requests.request(**req_kwargs)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/red]")
        sys.exit(1)
    duration = time.time() - start_time

    # Display response status and time.
    console.print(f"[bold green]Status Code:[/bold green] {response.status_code}")
    console.print(f"[bold yellow]Time Taken:[/bold yellow] {duration:.2f} seconds\n")

    # Display response headers in a table.
    headers_table = Table(title="Response Headers", box=box.SIMPLE)
    headers_table.add_column("Header", style="cyan", no_wrap=True)
    headers_table.add_column("Value", style="magenta")
    for key, value in response.headers.items():
        headers_table.add_row(key, value)
    console.print(headers_table)

    # Print the response body.
    console.print("\n[bold blue]Response Body:[/bold blue]")
    content_type = response.headers.get("Content-Type", "")
    body = response.text

    if "application/json" in content_type:
        try:
            json_obj = response.json()
            formatted_json = json.dumps(json_obj, indent=2)
            syntax = Syntax(formatted_json, "json", theme="monokai", line_numbers=True)
            console.print(syntax)
        except json.JSONDecodeError:
            console.print(body)
    else:
        console.print(body)

if __name__ == "__main__":
    main()
