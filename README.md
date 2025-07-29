# Log File Analyzer for Intrusion Detection
A Python-based tool to parse Apache log files, detect suspicious activity (Brute-force, Scanning, DoS), check IPs against a blacklist and AbuseIPDB, and generate detailed CSV, JSON, and visual reports.

## Folder Structure
```
log_analyzer_advanced/
├── blacklist/
│ └── known_bad_ips.txt # List of manually blacklisted IPs
├── data/
│ └── sample_apache.log # (Optional) Sample Apache log file
├── reports/
│ ├── detailed_report.csv # Auto-generated CSV report
│ ├── detailed_report.json # Auto-generated JSON report
│ └── ip_chart.png # Auto-generated bar chart of IP activity
├── .env # Stores sensitive API key
├── main.py # Main script to run the tool
└── requirements.txt # Python dependencies
```

## Features
- Parses Apache log files  
- Detects brute-force, DoS, and scanning behavior  
- Integrates with [AbuseIPDB](https://www.abuseipdb.com/) for IP reputation  
- Uses a local blacklist for known bad IPs  
- Generates visual and structured reports  
- Works on standard Apache access logs  

## Setup & Installation
### 1. Clone the Repo
```bash
git clone https://github.com/yourusername/log_analyzer_advanced.git
cd log_analyzer_advanced
```
### 2. Create & Activate Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
### 3. Install Dependencies
```bash
pip install -r requirements.txt
```
## .env Setup
Create a .env file in the root directory:
```bash
touch .env
```
Add your AbuseIPDB API key:
```bash
ABUSEIPDB_API_KEY=your_actual_key_here
```
In main.py, replace:
```python
ABUSEIPDB_API_KEY = "YOUR_API_KEY_HERE"
```
with:
```python
from dotenv import load_dotenv
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
```

## Usage
Run the tool:
```bash
python main.py
```
You’ll be prompted to enter the path to your Apache log file, e.g.:
```
Enter path to Apache log file (e.g., data/sample_apache.log):
```
Once complete, check the reports/ folder for:
- detailed_report.csv
- detailed_report.json
- ip_chart.png

## Detection Logic	

- Checked against the blacklist

- Queried via AbuseIPDB

- Tagged with detection type(s)

## Dependencies
Add this to your requirements.txt:

requests
matplotlib
python-dotenv

Install with:
```bash
pip install -r requirements.txt
```
