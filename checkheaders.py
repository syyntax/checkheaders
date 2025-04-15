#!/usr/bin/env python3

import argparse
import json
import re
import sys
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Header definitions with descriptions and validation functions
HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections, protecting against protocol downgrade attacks",
        "validate": lambda val: 'max-age=' in val.lower() and int(re.search(r'max-age=(\d+)', val.lower()).group(1)) >= 15768000
    },
    "Content-Security-Policy": {
        "description": "Controls which resources the browser is allowed to load, mitigating XSS attacks",
        "validate": lambda val: "default-src" in val or "script-src" in val
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling whether a page can be embedded in frames",
        "validate": lambda val: val.upper() in ["DENY", "SAMEORIGIN"]
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing, ensuring the browser honors the declared content type",
        "validate": lambda val: val.lower() == "nosniff"
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is included with requests",
        "validate": lambda val: val.lower() in ["no-referrer", "no-referrer-when-downgrade", "same-origin", 
                                               "strict-origin", "strict-origin-when-cross-origin"]
    },
    "Permissions-Policy": {
        "description": "Controls which browser features and APIs can be used on the page",
        "validate": lambda val: len(val) > 0  # Basic check that it's not empty
    },
    "X-XSS-Protection": {
        "description": "Legacy header to enable browser's XSS filtering (modern browsers use CSP instead)",
        "validate": lambda val: val in ["1", "1; mode=block"]
    },
    "Cache-Control": {
        "description": "Controls browser caching, can prevent sensitive data from being cached",
        "validate": lambda val: "no-store" in val.lower() or "private" in val.lower()
    }
}

def check_headers(url, verify_ssl=True):
    """Check security headers for the given URL"""
    try:
        # Add User-Agent to avoid being blocked
        headers = {'User-Agent': 'Mozilla/5.0 SecurityHeadersChecker/1.0'}
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True, verify=verify_ssl)
        
        # Check if we were redirected to HTTPS
        final_url = response.url
        
        # Verify hostname is the same after redirection (to prevent open redirects)
        original_host = urlparse(url).netloc
        final_host = urlparse(final_url).netloc
        
        if original_host != final_host:
            print(f"{Fore.YELLOW}[!!] Warning: Request was redirected to a different host: {final_host}")
        
        # Prepare results
        results = {
            "url": url,
            "final_url": final_url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "assessment": {}
        }
        
        # Print raw headers
        print(f"\n{Fore.CYAN}Raw Headers:{Style.RESET_ALL}")
        for header, value in response.headers.items():
            print(f"{Fore.CYAN}{header}{Style.RESET_ALL}: {value}")
        
        print(f"\n{Fore.CYAN}Security Headers Assessment:{Style.RESET_ALL}")
        
        # Check each security header
        for header, config in HEADERS.items():
            # Handle case-insensitive header names
            header_value = None
            for response_header, value in response.headers.items():
                if response_header.lower() == header.lower():
                    header_value = value
                    break
            
            if header_value is None:
                # Header is missing
                print(f"{Fore.RED}[X] {header}{Style.RESET_ALL}")
                print(f"    {Fore.RED}Missing header. {config['description']}")
                results["assessment"][header] = {
                    "status": "missing",
                    "value": None,
                    "description": config["description"]
                }
            else:
                # Header exists, check if it's properly configured
                is_secure = config["validate"](header_value)
                
                if is_secure:
                    print(f"{Fore.GREEN}[✓] {header}{Style.RESET_ALL}")
                    print(f"    {Fore.GREEN}Value: {header_value}")
                    print(f"    {Fore.GREEN}{config['description']}")
                    results["assessment"][header] = {
                        "status": "secure",
                        "value": header_value,
                        "description": config["description"]
                    }
                else:
                    print(f"{Fore.YELLOW}[!!] {header}{Style.RESET_ALL}")
                    print(f"    {Fore.YELLOW}Value: {header_value}")
                    print(f"    {Fore.YELLOW}Insecurely configured. {config['description']}")
                    results["assessment"][header] = {
                        "status": "insecure",
                        "value": header_value,
                        "description": config["description"]
                    }
        
        return results
    
    except requests.exceptions.SSLError as e:
        if verify_ssl:
            print(f"{Fore.YELLOW}SSL verification failed. Retrying with SSL verification disabled...")
            return check_headers(url, verify_ssl=False)
        else:
            print(f"{Fore.RED}Error: SSL error even with verification disabled: {e}")
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error: {e}")
        sys.exit(1)

def save_to_json(results, filename):
    """Save results to a JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{Fore.GREEN}Results saved to {filename}")
    except Exception as e:
        print(f"{Fore.RED}Error saving to JSON: {e}")

def main():
    parser = argparse.ArgumentParser(description='Check web server security headers')
    parser.add_argument('-u', '--url', required=True, help='URL to check')
    parser.add_argument('-j', '--json', help='Save results to JSON file')
    parser.add_argument('-k', '--insecure', action='store_true', help='Allow insecure server connections when using SSL')
    
    args = parser.parse_args()
    
    # Ensure URL has a scheme
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"{Fore.CYAN}Checking security headers for: {url}")
    results = check_headers(url, verify_ssl=not args.insecure)
    
    if args.json:
        save_to_json(results, args.json)

if __name__ == "__main__":
    main()