# log_analyzer_advanced/main.py

import re
import csv
import os
import requests
import json
import matplotlib.pyplot as plt
from collections import Counter, defaultdict

# === CONFIG ===
while True:
    LOG_FILE = input("Enter path to Apache log file (e.g., data/sample_apache.log): ")
    if os.path.exists(LOG_FILE):
        break
    print("❌ File not found. Please enter a valid path.")

BLACKLIST_FILE = "blacklist/known_bad_ips.txt"
CSV_REPORT = "reports/detailed_report.csv"
JSON_REPORT = "reports/detailed_report.json"
CHART_FILE = "reports/ip_chart.png"
THRESHOLD_403 = 5
DOS_THRESHOLD = 100
SCAN_THRESHOLD = 10
ABUSEIPDB_API_KEY = "YOUR_API_KEY_HERE"

# === PARSE LOG ===
def parse_apache_log(filepath):
    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] \"[A-Z]+ (.*?) HTTP/1.1\" (\d{3})')
    logs = []
    with open(filepath, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                ip, timestamp, path, status = match.groups()
                logs.append({
                    'ip': ip,
                    'time': timestamp,
                    'path': path,
                    'status': int(status),
                    'message': line.strip()
                })
    return logs

# === DETECTION FUNCTIONS ===
def detect_brute_force(logs, threshold=THRESHOLD_403):
    attempts = defaultdict(int)
    for log in logs:
        if "/login" in log['path'].lower() or log['status'] in [401, 403]:
            attempts[log['ip']] += 1
    return {ip: count for ip, count in attempts.items() if count >= threshold}

def detect_scanning(logs, threshold=SCAN_THRESHOLD):
    path_map = defaultdict(set)
    for log in logs:
        path_map[log['ip']].add(log['path'])
    return {ip: len(paths) for ip, paths in path_map.items() if len(paths) >= threshold}

def detect_dos(logs, threshold=DOS_THRESHOLD):
    ip_times = defaultdict(list)
    for log in logs:
        ip_times[log['ip']].append(log['time'])

    dos_candidates = {}
    for ip, times in ip_times.items():
        if len(times) >= threshold:
            dos_candidates[ip] = len(times)
    return dos_candidates

# === BLACKLIST ===
def load_blacklist(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath, 'r') as f:
        return set(line.strip() for line in f if line.strip())

# === API INTEGRATION ===
def check_ip_reputation(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()['data']
            return {
                'abuseScore': data.get('abuseConfidenceScore', 0),
                'country': data.get('countryCode', 'Unknown')
            }
    except:
        pass
    return {'abuseScore': 0, 'country': 'Unknown'}

# === REPORTING ===
def generate_reports(ip_info, csv_path, json_path):
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Country', 'Abuse Score', 'Blacklisted', 'Detected As'])
        for entry in ip_info:
            writer.writerow([entry['ip'], entry['country'], entry['abuseScore'], entry['blacklisted'], entry['detectedAs']])

    with open(json_path, 'w') as f:
        json.dump(ip_info, f, indent=4)

# === VISUALIZATION ===
def draw_chart(ip_counts, chart_path):
    os.makedirs(os.path.dirname(chart_path), exist_ok=True)
    ips = list(ip_counts.keys())
    counts = list(ip_counts.values())
    plt.figure(figsize=(10, 5))
    plt.bar(ips, counts, color='red')
    plt.xticks(rotation=45)
    plt.xlabel("IP Address")
    plt.ylabel("Suspicious Activity Count")
    plt.title("Top Suspicious IPs")
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()

# === MAIN ===
def main():
    logs = parse_apache_log(LOG_FILE)
    blacklist = load_blacklist(BLACKLIST_FILE)

    brute_ips = detect_brute_force(logs)
    scan_ips = detect_scanning(logs)
    dos_ips = detect_dos(logs)

    combined_ips = set(brute_ips) | set(scan_ips) | set(dos_ips)

    ip_info = []
    ip_chart_data = {}

    for ip in combined_ips:
        rep = check_ip_reputation(ip)
        detected_as = []
        if ip in brute_ips: detected_as.append("Brute-force")
        if ip in scan_ips: detected_as.append("Scanning")
        if ip in dos_ips: detected_as.append("DoS")
        ip_chart_data[ip] = brute_ips.get(ip, 0) + scan_ips.get(ip, 0) + dos_ips.get(ip, 0)
        ip_info.append({
            'ip': ip,
            'country': rep['country'],
            'abuseScore': rep['abuseScore'],
            'blacklisted': 'YES' if ip in blacklist else 'NO',
            'detectedAs': ', '.join(detected_as)
        })

    generate_reports(ip_info, CSV_REPORT, JSON_REPORT)
    draw_chart(ip_chart_data, CHART_FILE)
    print("✅ Full report generated with API data, blacklist, and refined detection logic!")

if __name__ == "__main__":
    main()