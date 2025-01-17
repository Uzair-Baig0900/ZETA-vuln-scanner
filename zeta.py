import subprocess
import sys
import os

def display_banner():
    """Display the banner with ASCII art and details."""
    print("ZETA-scan")
    print("BY - TEAM-ZETA")
    print("UZAIR AMJAD\n")

def print_banner():
    banner = """
===========================================
               Uzair Amjad                
         Basic  Scanner  Menu         
===========================================
"""
    print(banner)

def run_script(script_name, args=None):
    """Run a script with optional arguments."""
    try:
        print(f"Executing command: {sys.executable} {script_name} {' '.join(args) if args else ''}")
        command = [sys.executable, script_name]  # Use the current Python executable
        if args:
            command.extend(args)
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running {script_name}: {e}")
        print("Ensure Python is installed and accessible. Example: python3 or python.")
        print("Try running with appropriate flags:")
        print("Example: python3 zeta_scan.py --host example.com --threads 4 --verbose")

def main():
    display_banner()  # Show the banner before the menu

    print("Welcome to ZETA Vulnerability Scanner ")
    print("Select an option:\n")
    print("1 - Try Payloads on Web (SQLi, XSS, etc.)")
    print("2 - Scan for Vulnerabilities on System or Web")
    print("3 - Exit")

    choice = input("Enter your choice (1, 2, or 0): ")

    if choice == "1":
        print("\n Starting Payload Testing on Web...\n")
        target_url = input("Enter the target URL (e.g., example.com): ")
        verbose = input("Enable verbose mode? (y/n): ").lower()

        # Prepare the arguments
        args = ["--host", target_url, "--threads", "4"]  # Default to 4 threads
        if verbose == "y":
            args.append("--verbose")

        # Show progress and run the script
        print(f"\n Running ZETA-scan on {target_url}...\n")
        run_script("zeta_scan.py", args)
        print(f"\n Payload Testing completed. Report saved to {target_url}_payload_report.txt\n")

    elif choice == "2":
        print("\n Starting Vulnerability Scanning...\n")
        target_ip = input("Enter the target IP or domain: ")
        verbose = input("Enable verbose mode? (y/n): ").lower()
        report_file = f"{target_ip}_vuln_report.txt"
        
        # Prepare arguments for zeta_vuln.py
        args = ["--host", target_ip]
        if verbose == "y":
            args.append("--verbose")
        
        print(f"\n Running zeta-scan on {target_ip}...\n")
        
        # Check if the script exists
        if not os.path.isfile("zeta_vuln.py"):
            print("zeta_vuln.py script not found!")
        else:
            run_script("zeta_vuln.py", args)
        print(f"\n Vulnerability Scanning completed. Report saved to {report_file}\n")

    elif choice == "0":
        print("\n Exiting the scanner. Have a great day!")
    else:
        print("\nInvalid choice. Please try again.")

if __name__ == "__main__":
    main()
