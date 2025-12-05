#  Video Presentation
> Video (Unlisted YouTube):(https://youtu.be/Q6N4ENsnkB0)

Team Rocket Network Automation Project
---

# README.md

# Automated Recon Output Parsing and Alerting System

*A modular Python tool for converting raw network scan data into structured reports and actionable security insights.*

---

## Overview

This project automates the process of analyzing network reconnaissance data by transforming raw scan outputs into organized, human-readable reports. Traditional tools like Nmap provide valuable information, but their output can be difficult to interpret at scale. This system bridges that gap by parsing scan results, storing them in a structured database, applying security policies, and generating reports that highlight both normal behavior and potential risks.

The tool is modeled after real security workflows and behaves like a simplified vulnerability assessment engine. It supports automatic detection of unexpected ports and correlation of detected services against known vulnerabilities.

---

## **Key Features**

### **Automated Parsing**

Reads Nmap XML scan results and converts them into a normalized, structured format that is easy to analyze and store.

### **SQLite Data Storage**

Stores parsed scan results in a reliable SQLite database, supporting historical review, comparison, and querying.

### **Expected Ports Policy Check**

Compares detected open ports against a YAML-defined baseline and alerts on any port not included in the expected list.

### Markdown Reporting

Generates clean and readable Markdown reports summarizing hosts, open ports, detected services, and anomalies.

### Vulnerability Correlation

Matches detected services and version numbers against known vulnerability signatures defined in YAML, producing a vulnerability risk report.

### Modular Orchestrator

Coordinates the entire workflow including parsing, storing, evaluating, and reporting. Users trigger the entire pipeline through a single command.

---

## Repository Structure

```
project-root/
│
├── src/                     # Main Python source code
│   ├── orchestrator.py
│   ├── vuln_correlation.py
│   └── additional modules
│
├── config/                  # Configuration and signature files
│   ├── expected_ports.yaml
│   └── vuln_signatures.yaml
│
├── sample_data/             # Example scan files for testing
│
├── reports/                 # Example generated reports (optional)
│
├── docs/                    # Documentation, writeups, diagrams
│
├── tests/                   # Automated tests for components
│
├── requirements.txt         # Python dependencies
├── .gitignore
└── README.md
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ifeakindipe1/IT-359-Group-Project.git
cd IT-359-Group-Project
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Run the orchestrator

The orchestrator executes the entire pipeline: parsing, database storage, policy checking, reporting, and vulnerability correlation.

```bash
python3 -m src.orchestrator \
  --input sample_data/huge_nmap_sample.xml \
  --output-dir output \
  --expected-ports config/expected_ports.yaml \
  --sqlite output/recon.db \
  --report-md output/recon_report.md \
  --vuln-signatures config/vuln_signatures.yaml \
  --vuln-report-md output/vuln_report.md \
  --dry-run
```

### Generated Reports

This command produces:

A recon report that organizes hosts, ports, and services
An alerts report identifying unexpected ports
A vulnerability risk report that highlights exposed services and potential vulnerabilities

---

## Example Outputs

Recon Report (Markdown)
Summarizes hosts and detected open ports in a readable structure.

Alerts Report
Highlights unexpected or suspicious ports.

Vulnerability Risk Report
Identifies potential security risks based on version information.

You may place sample reports in the reports folder for instructor review.

---

## Architecture Overview

The system operates in several stages:

Structured parsing of Nmap scan output
Storage of findings in SQLite for persistence
Evaluation of ports against an approved policy
Generation of readable Markdown reports
Correlation of services with known vulnerabilities
Automation of the entire process through an orchestrator script

This modular design mirrors how real security tools are architected and allows future extension without rewriting the system.



## Sample Nmap Input

```
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.4p1
80/tcp   open  http        Apache httpd 2.4.57
443/tcp  open  ssl/http    nginx 1.17.10
3306/tcp open  mysql       MySQL 5.7.35
```

System converts this raw scan data into structured analysis and meaningful security insights.
