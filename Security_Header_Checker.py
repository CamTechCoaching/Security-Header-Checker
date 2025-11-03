# Banner Grabber & Security Header Checker
# Fetches HTTP headers from a URL, saves them to a file, and checks for important security headers

import requests
import re

def is_valid_url(url: str) -> bool:
    """
    Validate a URL using regex.
    Requires http:// or https:// and a valid domain.
    """
    regex = re.compile(
        r'^(https?:\/\/)'            # Require http:// or https://
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,6})'  # Domain name
    )
    return re.match(regex, url) is not None


def grab_banner(url: str, user_agent: str) -> None:
    """
    Fetch HTTP headers from the URL using the specified User-Agent.
    Prints headers, writes them to a file, and checks security headers.
    """
    headers = {'User-Agent': user_agent}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()  # Raise for HTTP errors
        
        # Print headers to console
        print("\nHTTP Headers (Banner):\n")
        for header, value in response.headers.items():
            print(f"{header}: {value}")
        
        # Save headers to a file
        with open("headers_output.txt", "w") as file:
            file.write(f"Headers for {url}\n\n")
            for header, value in response.headers.items():
                file.write(f"{header}: {value}\n")
        print("\nHeaders saved to 'headers_output.txt'\n")
        
        # Check for important security headers
        check_security_headers(response.headers)
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}")


def check_security_headers(headers: dict) -> None:
    """
    Check for presence of common security-related headers.
    """
    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-XSS-Protection",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]
    
    print("\nSecurity Headers Check:\n")
    for header in security_headers:
        if header in headers:
            print(f" {header}: Present")
        else:
            print(f" {header}: Missing (Consider adding it)")


if __name__ == "__main__":
    url = input("Enter the target URL: ").strip()
    user_agent = input("Enter a custom User-Agent (or press Enter to use default): ").strip()
    
    if not user_agent:
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    
    if is_valid_url(url):
        grab_banner(url, user_agent)
    else:
        print("Invalid URL. Please enter a valid URL with http:// or https://")
