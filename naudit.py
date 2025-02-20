import os
import subprocess
import re
import json
from jinja2 import Template
from prerequisites import check_prerequisites

# Check for required tools
check_prerequisites()

# Detect subnet
def get_subnet():
    try:
        output = subprocess.check_output("ip route | grep src | awk '{print $1}'", shell=True)
        subnet = output.decode().strip()
        print(f"[+] Detected subnet: {subnet}")
        return subnet
    except Exception as e:
        print(f"[-] Failed to detect subnet: {e}")
        exit(1)

# Step 1: Scan for live hosts
def scan_live_hosts(subnet):
    print("[+] Scanning for live hosts...")
    live_hosts = []
    result = subprocess.run(f"nmap -sn {subnet} -oG -", shell=True, capture_output=True, text=True)

    for line in result.stdout.split("\n"):
        match = re.search(r"Host: (\d+\.\d+\.\d+\.\d+)", line)
        if match:
            live_hosts.append(match.group(1))

    print(f"[+] Found {len(live_hosts)} live hosts")
    return live_hosts

# Step 2: Masscan for fast port discovery
def masscan_scan(targets):
    print("[+] Running Masscan for quick port discovery...")

    if not targets:
        print("[-] No live hosts detected.")
        return {}

    output_file = "masscan_results.txt"
    target_ips = " ".join(targets)

    # Fix: Use --wait=1 to prevent Masscan from stalling
    cmd = f"masscan {target_ips} -p1-65535 --rate=5000 --wait=1 -oG {output_file}"
    os.system(cmd)

    open_ports = {}

    try:
        with open(output_file, "r") as file:
            for line in file:
                match = re.search(r"Host: (\d+\.\d+\.\d+\.\d+) .*Ports: ([\d,/]+)", line)
                if match:
                    ip = match.group(1)
                    ports_raw = match.group(2).replace("/", ",").split(",")
                    ports_clean = [int(port.strip()) for port in ports_raw if port.strip().isdigit()]  # Only take valid numbers

                    if ports_clean:
                        open_ports[ip] = ports_clean
    except FileNotFoundError:
        print("[-] Error: Masscan output file not found. Check if Masscan ran correctly.")
    
    print(f"[+] Masscan completed. Found open ports on {len(open_ports)} hosts.")
    return open_ports

# Step 3: Nmap deep scan
def nmap_scan(targets_with_ports):
    print("[+] Running aggressive Nmap scan (-A -Pn)...")
    scan_results = {}

    for ip, ports in targets_with_ports.items():
        port_list = ",".join(map(str, ports))

        # Run aggressive Nmap scan
        cmd = f"nmap -A -Pn -p{port_list} {ip} -oN nmap_{ip}.txt"
        os.system(cmd)

        # Ensure parsed results are stored as a dictionary
        parsed_results = parse_nmap_results(f"nmap_{ip}.txt")
        if isinstance(parsed_results, dict):
            scan_results[ip] = parsed_results
        else:
            print(f"[-] Warning: Invalid data structure for {ip}, skipping.")

    print("[+] Nmap scanning completed.")
    return scan_results  # Always return a dictionary


# Step 4: Parse Nmap results
def parse_nmap_results(filename):
    services = {}

    try:
        with open(filename, "r") as file:
            for line in file:
                match = re.search(r"(\d+)/(\w+)\s+open\s+(\S+)", line)
                if match:
                    port, proto, service = match.groups()
                    services[int(port)] = {"protocol": proto, "service": service}

    except FileNotFoundError:
        print(f"[-] Error: Nmap output file {filename} not found.")
    
    return services  # Ensure this is always a dictionary


# Step 5: Generate HTML report
def generate_report(scan_data):
    print("[+] Generating report...")

    # Ensure reports directory exists
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    # Debugging: Print scan_data structure
    print("DEBUG: scan_data =", scan_data)
    print("DEBUG: Type of scan_data['results'] =", type(scan_data["results"]))

    # Ensure scan_data is correctly formatted
    if not isinstance(scan_data, dict) or "results" not in scan_data:
        print("[-] Error: scan_data is not in the expected format.")
        return

    if not isinstance(scan_data["results"], dict):
        print("[-] Error: scan_data['results'] is not a dictionary.")
        return

    # Load correct HTML template
    template_path = "templates/report.html"
    if not os.path.exists(template_path):
        print(f"[-] Error: Template file {template_path} not found.")
        return

    with open(template_path, "r", encoding="utf-8") as file:
        template = Template(file.read())

    try:
        report_content = template.render(scan_data=scan_data)
    except Exception as e:
        print(f"[-] Jinja2 Rendering Error: {e}")
        return

    report_path = os.path.join(reports_dir, "naudit_report.html")

    # Ensure we are writing actual HTML and not raw Python code
    with open(report_path, "w", encoding="utf-8") as file:
        file.write(report_content)

    print(f"[+] Report successfully generated: {report_path}")

    # Debugging: Confirm report content is HTML
    with open(report_path, "r", encoding="utf-8") as file:
        first_line = file.readline()
        print(f"[DEBUG] First line of report: {first_line}")


# Run audit
subnet = get_subnet()
live_hosts = scan_live_hosts(subnet)
ports = masscan_scan(live_hosts)
scan_results = nmap_scan(ports)

# Generate report
generate_report({"results": scan_results})
print("[+] Report successfully generated: reports/naudit_report.html")

