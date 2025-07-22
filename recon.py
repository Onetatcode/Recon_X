# recon_tool.py (fixed version)
import socket
import whois
import dns.resolver
import requests
import nmap
from datetime import datetime
import sys

# === LOGGING ===
def log_action(action, data=""):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("session_log.txt", "a") as log_file:
        log_file.write(f"[{now}] ACTION: {action}\n")
        if data:
            log_file.write(str(data) + "\n")
        log_file.write("="*60 + "\n")

# === FUNCTIONS ===
def get_whois(domain):
    try:
        w = whois.whois(domain)
        log_action("WHOIS", str(w))
        return str(w)
    except Exception as e:
        return f"WHOIS error: {e}"

def get_dns_records(domain):
    results = {}
    try:
        for record_type in ["A", "MX", "TXT", "NS"]:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [r.to_text() for r in answers]
    except Exception as e:
        results["Error"] = str(e)
    log_action("DNS Records", results)
    return results

def get_subdomains_crtsh(domain):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code != 200:
            raise Exception(f"crt.sh returned {res.status_code}")
        data = res.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value")
            if name:
                for sub in name.split("\n"):
                    if domain in sub:
                        subdomains.add(sub.strip())
        subdomains = sorted(list(subdomains))
        log_action("Subdomain Enumeration", subdomains)
        return subdomains
    except Exception as e:
        return [f"Subdomain enum error: {e}"]

def scan_ports(domain):
    try:
        nm = nmap.PortScanner()
        nm.scan(domain, '1-1000', arguments='-T4 -sS')
        ports = nm[domain].tcp()
        log_action("Port Scan", ports)
        return ports
    except Exception as e:
        return {"Error": str(e)}

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner if banner else "No response"
    except:
        return "Banner grab failed"

def generate_report(domain, data):
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{domain}_recon_{now}.txt"
    with open(filename, "w") as f:
        f.write(f"🔍 Recon Report for: {domain}\n")
        f.write(f"🕒 Timestamp: {now}\n")
        f.write("="*60 + "\n\n")

        for section, value in data.items():
            f.write(f"📘 {section} Results\n")
            f.write("-" * 50 + "\n")
            if isinstance(value, dict):
                for k, v in value.items():
                    f.write(f"{k}: {v}\n")
            elif isinstance(value, list):
                for item in value:
                    f.write(f"- {item}\n")
            else:
                f.write(f"{value}\n")
            f.write("\n")
    log_action("Report Generated", f"{filename}")
    return filename

# === MENU ===
def menu():
    print("\n🛡️  ITSOLERA RECON TOOL")
    print("="*40)
    print("1. WHOIS Lookup")
    print("2. DNS Records")
    print("3. Subdomain Enumeration")
    print("4. Port Scan + Banner Grab")
    print("5. Generate Final Report")
    print("6. Exit")
    print("="*40)

# === MAIN ===
if __name__ == "__main__":
    result = {}
    print("Enter target domain (e.g. example.com):")
    domain = input(">> ").strip()
    log_action("Session Started", f"Target: {domain}")

    resolved_ip = ""
    try:
        resolved_ip = socket.gethostbyname(domain)
    except:
        print("❌ Could not resolve domain to IP. Port scan may fail.")

    while True:
        menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            print("[+] WHOIS Lookup...")
            result["WHOIS"] = get_whois(domain)
            print("[✔] Done.")

        elif choice == "2":
            print("[+] Fetching DNS records...")
            result["DNS"] = get_dns_records(domain)
            print("[✔] Done.")

        elif choice == "3":
            print("[+] Enumerating subdomains...")
            result["Subdomains"] = get_subdomains_crtsh(domain)
            print("[✔] Done.")

        elif choice == "4":
            print("[+] Scanning ports...")
            ports = scan_ports(domain)
            banners = {}
            for port in ports:
                if isinstance(ports[port], dict) and ports[port].get("state") == "open":
                    banner = banner_grab(resolved_ip, port)
                    banners[port] = {
                        "state": ports[port]["state"],
                        "banner": banner
                    }
            result["Ports"] = banners
            print("[✔] Port scan and banner grabbing done.")

        elif choice == "5":
            print("[+] Generating report...")
            filename = generate_report(domain, result)
            print(f"[✔] Report saved: {filename}")

        elif choice == "6":
            log_action("Session Ended")
            print("Exiting.")
            sys.exit()

        else:
            print("❌ Invalid option.")
