"""
seed.py — Fill the database with realistic test data so your
IOC checker has something to find.
Run once: python seed.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from api.database import init_db, insert_report, upsert_metadata

MALICIOUS_IPS = [
    ("45.33.32.156",  "US", "Linode LLC",       "Data Center", 80, False),
    ("185.220.101.5", "DE", "Tor Project",       "Tor",         95, True),
    ("203.0.113.99",  "CN", "ChinaNet",          "ISP",         70, False),
]

SUSPICIOUS_IPS = [
    ("198.51.100.7",  "RU", "Selectel",          "Data Center", 35, False),
    ("192.0.2.55",    "BR", "Claro",             "ISP",         20, False),
]

CLEAN_IPS = [
    ("8.8.8.8",   "US", "Google LLC",   "Content Delivery Network", 0, False),
    ("1.1.1.1",   "AU", "Cloudflare",   "Content Delivery Network", 0, False),
]

CATEGORIES = {
    18: "Brute-Force",
    22: "Hacking",
    14: "Port Scan",
    4:  "DDoS Attack",
}

REPORTERS = [
    "10.0.0.1", "10.0.0.2", "10.0.0.3",
    "172.16.0.1", "172.16.0.2", "192.168.1.100",
]

def seed():
    init_db()
    print("Seeding database...")

    for ip, country, isp, usage, report_count, is_tor in MALICIOUS_IPS:
        upsert_metadata(ip, country_code=country, isp=isp,
                        usage_type=usage, is_tor=int(is_tor))
        for i in range(report_count):
            cat = list(CATEGORIES.keys())[i % len(CATEGORIES)]
            reporter = REPORTERS[i % len(REPORTERS)]
            insert_report(ip, cat, f"Automated abuse report — {CATEGORIES[cat]}", reporter)
        print(f"  {ip} — {report_count} reports (malicious)")

    for ip, country, isp, usage, report_count, is_tor in SUSPICIOUS_IPS:
        upsert_metadata(ip, country_code=country, isp=isp,
                        usage_type=usage, is_tor=int(is_tor))
        for i in range(report_count):
            cat = list(CATEGORIES.keys())[i % len(CATEGORIES)]
            reporter = REPORTERS[i % len(REPORTERS)]
            insert_report(ip, cat, f"Suspicious activity — {CATEGORIES[cat]}", reporter)
        print(f"  {ip} — {report_count} reports (suspicious)")

    for ip, country, isp, usage, _, is_tor in CLEAN_IPS:
        upsert_metadata(ip, country_code=country, isp=isp,
                        usage_type=usage, is_tor=0)
        print(f"  {ip} — 0 reports (clean)")

    print("\nDone. Start the API with:  uvicorn main:app --reload")

if __name__ == "__main__":
    seed()