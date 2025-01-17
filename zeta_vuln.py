import subprocess
import argparse
import sys

def display_banner():
    """Display the banner with ASCII art and details."""
    print("ZETA-Pro")
    print("BY - TEAM-ZETA")
    print("UZAIR AMJAD\n")

def run_nmap_scan(host, verbose, report_file):
    """Run Nmap scan and save the result to a report file."""
    nmap_command = ["nmap", "-v", host, "--script", "vuln"]

    if verbose:
        print(f"Running Nmap on {host} with verbose output...")

    try:
        # Run Nmap and capture the output
        result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        # Save the output to the report file
        with open(report_file, "w") as file:
            file.write(result.stdout)  # Write the Nmap output to the report file

        if verbose:
            print(result.stdout)  # Print detailed output to console (if verbose)
    
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed: {e.stderr}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanning")
    parser.add_argument('--host', required=True, help='Target IP or domain')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    # Display the banner
    display_banner()

    # Ensure Nmap is installed
    try:
        subprocess.run(["nmap", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("Nmap is not installed or not in the system's PATH.")
        sys.exit(1)

    # Generate the report filename based on the target IP
    report_file = f"{args.host}_vuln_report.txt"

    # Run the Nmap scan and save the result to the report file
    run_nmap_scan(args.host, args.verbose, report_file)

    print(f"Vulnerability Scanning completed. Report saved to {report_file}\n")

if __name__ == "__main__":
    main()
