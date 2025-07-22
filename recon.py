# recon_menu_tool_with_logs.py
import socket
import whois
import dns.resolver
import requests
import nmap
from datetime import datetime
import sys

# === LOGGING FUNCTION ===
def log_action(action, data=""):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("session_log.txt", "a") as log_file:
        log_file.write(f"[{now}] ACTION: {action}\n")
        if data:
            if isinstance(data, (dict, list)):
                log_file.write(f"{str(data)}\n")
            else:
                log_file.write(data + "\n")
        log_file.write("="*60 + "\n")

def get_whois(domain):
    try:
        w = whois.whois(domain)
        log_action("WHOIS Lookup", str(w))
        return str(w)
    except Exception as e:
        log_action("WHOIS Error", str(e))
        return f"WHOIS Error: {e}"

def get_dns_records(domain):
    records = {}
    try:
        for record_type in ['A', 'MX', 'TXT', 'NS']:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [r.to_text() for r in answers]
    except Exception as e:
        records['Error'] = str(e)
    log_action("DNS Records", records)
    return records

def get_subdomains_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, timeout=10)
        data = res.json()
        subdomains = list(set(entry['name_value'] for entry in data))
        log_action("Subdomain Enumeration", subdomains)
        return subdomains
    except Exception as e:
        log_action("Subdomain Enum Error", str(e))
        return [f"Subdomain enum error: {e}"]

def scan_ports(domain):
    nm = nmap.PortScanner()
    try:
        nm.scan(domain, '1-1000', arguments='-T4 -sS')
        log_action("Port Scan", nm[domain].tcp())
        return nm[domain].all_protocols(), nm[domain].tcp()
    except Exception as e:
        log_action("Port Scan Error", str(e))
        return [f"Port scan error: {e}"]

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        log_action(f"Banner Grab on {port}", banner)
        return banner
    except:
        return "No banner"

def generate_report(domain, data):
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{domain}_recon_{now}.txt"
    with open(filename, "w") as f:
        f.write(f"Recon Report for {domain}\n")
        f.write("="*50 + "\n")
        for key, val in data.items():
            f.write(f"\n[{key}]\n")
            if isinstance(val, dict):
                for k, v in val.items():
                    f.write(f"{k}: {v}\n")
            elif isinstance(val, list):
                for item in val:
                    f.write(f"- {item}\n")
            else:
                f.write(str(val) + "\n")
    log_action("Report Generated", f"Saved as {filename}")
    return filename

def menu():
    print("\n🛡️  ITSOLERA RECON TOOL - MENU")
    print("="*40)
    print("1. WHOIS Lookup")
    print("2. DNS Records")
    print("3. Subdomain Enumeration")
    print("4. Port Scan + Banner Grab")
    print("5. Generate Final Report")
    print("6. Exit")
    print("="*40)

# === Main Program ===
if __name__ == "__main__":
    result = {}
    print("🔍 Enter target domain (e.g., example.com):")
    domain = input(">> ").strip()
    log_action("Session Started", f"Target: {domain}")

    while True:
        menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            print("\n[+] Running WHOIS...")
            result["WHOIS"] = get_whois(domain)
            print("[✔] WHOIS completed.")

        elif choice == "2":
            print("\n[+] Fetching DNS Records...")
            result["DNS"] = get_dns_records(domain)
            print("[✔] DNS records fetched.")

        elif choice == "3":
            print("\n[+] Enumerating Subdomains...")
            result["Subdomains"] = get_subdomains_crtsh(domain)
            print("[✔] Subdomain enumeration done.")

        elif choice == "4":
            print("\n[+] Scanning Ports and Grabbing Banners...")
            protocols, ports = scan_ports(domain)
            port_data = {}
            for p in ports:
                banner = banner_grab(domain, p)
                port_data[p] = {"state": ports[p]['state'], "banner": banner}
            result["Ports"] = port_data
            print("[✔] Port scan complete.")

        elif choice == "5":
            print("\n[+] Generating report...")
            filename = generate_report(domain, result)
            print(f"[✔] Report saved to: {filename}")

        elif choice == "6":
            print("Exiting... 🚪")
            log_action("Session Ended")
            sys.exit()

        else:
            print("❌ Invalid option. Please try again.")
