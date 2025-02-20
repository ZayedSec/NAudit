import shutil
import sys

def check_prerequisites():
    required_tools = ["nmap", "masscan", "testssl.sh", "nikto"]
    missing = []

    print("[+] Checking for required tools...")

    for tool in required_tools:
        if shutil.which(tool):
            print(f"[✔] {tool} is installed.")
        else:
            print(f"[✘] {tool} is MISSING!")
            missing.append(tool)

    if missing:
        print("\n[-] The following tools are missing:")
        for tool in missing:
            print(f"   - {tool}")
        print("\nPlease install the missing tools and rerun the script.")
        sys.exit(1)

    print("[+] All prerequisites are installed.")

# Run the check if executed as a script
if __name__ == "__main__":
    check_prerequisites()

