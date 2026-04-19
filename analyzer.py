import email
import re
import os
import requests
from dotenv import load_dotenv
from colorama import Fore, Style, init

# Setup
init(autoreset=True)
load_dotenv()

VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

# ─────────────────────────────────────────
# STEP 1: Load the email file
# ─────────────────────────────────────────
def load_email(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return email.message_from_file(f)

# ─────────────────────────────────────────
# STEP 2: Extract IOCs from email
# ─────────────────────────────────────────
def extract_iocs(msg):
    raw = str(msg)

    ips      = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw)))
    urls     = list(set(re.findall(r'https?://[^\s"<>]+', raw)))
    domains  = list(set(re.findall(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', raw)))
    sender   = msg.get("From", "Unknown")
    subject  = msg.get("Subject", "Unknown")

    return {
        "sender": sender,
        "subject": subject,
        "ips": ips,
        "urls": urls,
        "domains": domains
    }

# ─────────────────────────────────────────
# STEP 3: Check IP against AbuseIPDB
# ─────────────────────────────────────────
def check_ip(ip):
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r    = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        data = r.json()["data"]
        return data["abuseConfidenceScore"], data.get("countryCode", "??")
    except:
        return None, None

# ─────────────────────────────────────────
# STEP 4: Check URL against VirusTotal
# ─────────────────────────────────────────
def check_url_vt(url_to_check):
    import base64
    url_id  = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    headers = {"x-apikey": VT_KEY}
    try:
        r     = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0)
    except:
        return None

# ─────────────────────────────────────────
# STEP 5: Print the Report
# ─────────────────────────────────────────
def generate_report(iocs):
    print("\n" + "="*55)
    print("       PHISHING EMAIL ANALYSIS REPORT")
    print("="*55)
    print(f"  From    : {iocs['sender']}")
    print(f"  Subject : {iocs['subject']}")

    # --- IPs ---
    print(f"\n{Fore.CYAN}[ IPs Found ]{Style.RESET_ALL}")
    if not iocs["ips"]:
        print("  None found.")
    for ip in iocs["ips"]:
        score, country = check_ip(ip)
        if score is not None:
            color = Fore.RED if score > 20 else Fore.GREEN
            label = "⚠ MALICIOUS" if score > 20 else "✓ Clean"
            print(f"  {ip} [{country}] → Abuse Score: {color}{score}% {label}")
        else:
            print(f"  {ip} → Could not check")

    # --- URLs ---
    print(f"\n{Fore.CYAN}[ URLs Found ]{Style.RESET_ALL}")
    if not iocs["urls"]:
        print("  None found.")
    for url in iocs["urls"][:5]:
        malicious = check_url_vt(url)
        if malicious is not None:
            color = Fore.RED if malicious > 0 else Fore.GREEN
            label = "⚠ MALICIOUS" if malicious > 0 else "✓ Clean"
            print(f"  {url}")
            print(f"  → Detections: {color}{malicious} engines flagged this {label}")
        else:
            print(f"  {url} → Could not check")

    # --- Domains ---
    print(f"\n{Fore.CYAN}[ Domains Found ]{Style.RESET_ALL}")
    for domain in iocs["domains"][:5]:
        print(f"  {domain}")

    # --- Final Verdict ---
    print(f"\n{Fore.CYAN}[ Final Verdict ]{Style.RESET_ALL}")
    all_clean = True
    for ip in iocs["ips"]:
        score, _ = check_ip(ip)
        if score and score > 20:
            all_clean = False
    for url in iocs["urls"][:5]:
        mal = check_url_vt(url)
        if mal and mal > 0:
            all_clean = False

    if all_clean:
        print(f"  {Fore.GREEN}✓ No threats detected. Email appears clean.")
    else:
        print(f"  {Fore.RED}⚠ SUSPICIOUS — Threats detected! Do NOT click any links.")

    print("="*55 + "\n")

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    print(f"{Fore.YELLOW}Loading email file...")
    msg  = load_email("test_email.eml")

    print(f"{Fore.YELLOW}Extracting IOCs...")
    iocs = extract_iocs(msg)

    print(f"{Fore.YELLOW}Checking threat feeds... (this may take 10-20 seconds)")
    generate_report(iocs)
with open("report.txt", "w") as f:
    f.write(f"From: {iocs['sender']}\n")
    f.write(f"Subject: {iocs['subject']}\n")
    f.write(f"Verdict: SUSPICIOUS\n")