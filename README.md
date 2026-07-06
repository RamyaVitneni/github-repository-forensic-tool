# Git Repository Forensics and Insider Code Tampering Investigation Tool
## Live Deployed Link

Live App: https://135.235.139.148/

## Project Overview

The **Git Repository Forensics and Insider Code Tampering Investigation Tool** is a cybersecurity and digital forensics project designed to analyze Git repositories and detect suspicious developer activities.

This tool helps investigators, developers, and security teams identify:

- Secret leakage in Git history
- Sensitive files committed or deleted
- Suspicious commits
- Large code deletions
- Authentication or security logic changes
- Author email mismatch
- Insider code tampering indicators
- Risk score and severity of findings

The tool accepts a **GitHub repository URL**, clones the repository locally, analyzes the complete Git commit history, and generates a dashboard and forensic report.

---

## Aim of the Project

The aim of this project is to design and develop an automated forensic tool that analyzes Git repository history to detect secret leakage, suspicious commits, deleted sensitive files, author identity mismatch, and possible insider code tampering.

---

## Purpose of the Project

In software development, source code is one of the most valuable assets of an organization. Developers use GitHub, GitLab, Bitbucket, or other Git-based platforms to manage and track code changes.

Sometimes sensitive information such as passwords, API keys, database credentials, private keys, or tokens may be committed accidentally. In other cases, a malicious insider may remove authentication logic, delete important files, or modify security-related code.

Manual analysis of Git history is time-consuming. This project automates the forensic analysis process and highlights suspicious activities clearly.

---

## Features

- GitHub repository URL input
- Automatic repository cloning
- Git commit history extraction
- Commit timeline reconstruction
- Secret detection
- Sensitive file detection
- Deleted file analysis
- Suspicious commit detection
- Author identity mismatch detection
- Risk score calculation
- Severity classification
- Dashboard visualization
- PDF forensic report generation

---

## Technologies Used

- Python
- GitPython
- Streamlit
- Pandas
- Plotly
- ReportLab
- SQLite
- Git

---

## Hardware Requirements

- Processor: Intel i3 or above
- RAM: Minimum 4 GB
- Storage: Minimum 5 GB free space
- Operating System: Windows / Linux

---

## Software Requirements

- Python 3.10 or above
- Git installed on system
- VS Code or PyCharm
- Internet connection for cloning GitHub repositories

---

## Project Folder Structure

```text
git-repository-forensics-tool/
│
├── app.py
├── requirements.txt
├── README.md
│
├── analyzer/
│   ├── git_collector.py
│   ├── secret_detector.py
│   ├── sensitive_file_detector.py
│   ├── suspicious_commit_detector.py
│   ├── author_analyzer.py
│   ├── risk_scoring.py
│   ├── scanner.py
│   ├── db.py
│   └── report_generator.py
│
├── cloned_repositories/
│
├── reports/
│
└── scripts/
    └── create_test_repo.py
Installation Steps
Step 1: Extract the Project ZIP

Extract the project ZIP file.

Open Command Prompt or PowerShell inside the project folder.

Example:

cd C:\Users\Hp\Downloads\git-repository-forensics-tool-github-url\git-repository-forensics-tool
Step 2: Create Virtual Environment
python -m venv venv

If python does not work, use:

py -m venv venv
Step 3: Activate Virtual Environment

For Command Prompt:

venv\Scripts\activate.bat

For PowerShell:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
venv\Scripts\activate
Step 4: Install Required Packages
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

If requirements.txt is not working, install manually:

python -m pip install streamlit gitpython pandas plotly reportlab
How to Run the Project

Run the Streamlit dashboard:

python -m streamlit run app.py

Or use the venv Python directly:

venv\Scripts\python.exe -m streamlit run app.py

After running, the dashboard will open in the browser:

http://localhost:8501
How to Use the Tool
Open the dashboard.
Enter a public GitHub repository URL.
Click the scan button.
The tool clones the repository locally.
The tool extracts commit history.
It scans commits, diffs, files, and authors.
It detects suspicious forensic findings.
Dashboard displays risk summary and findings.
Generate and download the forensic report.

Example GitHub URL format:

https://github.com/username/repository-name
Detection Modules
1. Git Metadata Collection

This module collects:

Commit hash
Author name
Author email
Commit date and time
Commit message
Files changed
Lines added
Lines deleted
2. Secret Detection

This module detects hardcoded secrets such as:

Passwords
API keys
JWT tokens
Secret keys
Database credentials
Private keys
Access tokens

Example:

DB_PASSWORD=admin123
3. Sensitive File Detection

This module detects sensitive files such as:

.env
credentials.txt
config.json
database.yml
private.key
id_rsa
settings.py
secrets.json
4. Deleted File Forensics

This module checks whether sensitive files were added and later deleted.

Even if a file is deleted from the latest version of a repository, it may still exist in Git history.

5. Suspicious Commit Detection

This module detects unusual commit behavior such as:

Large number of lines deleted
Many files modified in one commit
Suspicious commit messages
Authentication code removed
Security-related files modified
Commit made outside normal working hours

Suspicious keywords include:

bypass
disable auth
remove validation
temporary fix
hardcoded
backdoor
skip verification
6. Author Identity Analysis

This module checks whether the same author uses different email addresses.

Example:

developer@company.com
developer123@gmail.com

This may indicate misconfiguration, account misuse, or suspicious identity behavior.

7. Risk Scoring

Each finding is assigned a risk score.

Finding Type	Risk Score
Private key found	95
Password found	90
API token found	85
Sensitive file deleted	80
Authentication code removed	75
Large code deletion	70
Author email mismatch	50
Suspicious commit message	40

Severity levels:

Score Range	Severity
80–100	Critical
60–79	High
40–59	Medium
1–39	Low
Dashboard Output

The dashboard displays:

Repository name
Total commits analyzed
Total contributors
Suspicious commits
Secrets detected
Sensitive files found
Deleted sensitive files
High-risk findings
Commit timeline
Contributor activity
Risk score summary
Findings table
Report Generation

The tool generates a forensic investigation report containing:

Case ID
Repository name
Investigator name
Scan date
Repository summary
Timeline of suspicious activities
Secret leakage findings
Deleted file findings
Author mismatch findings
Risk score
Evidence
Recommendations
Conclusion
Sample Output
Case ID: GIT-CASE-001
Repository Name: Employee-Portal-App
Investigator Name: Ramya
Scan Date: 30-06-2026

Total Commits Analyzed: 42
Total Contributors: 5
Suspicious Commits: 6
Secrets Detected: 3
Deleted Sensitive Files: 2
High-Risk Findings: 4
Sample Findings
Finding 1: Hardcoded Database Password
Severity: Critical
Risk Score: 90
Recommendation: Rotate the exposed password and remove secrets from Git history.
Finding 2: Sensitive File Deleted
Severity: High
Risk Score: 80
Evidence: .env file was committed and deleted later
Recommendation: Review Git history and clean sensitive data securely.
Finding 3: Authentication Code Removed
Severity: High
Risk Score: 75
Evidence: Login validation code was removed from auth.py
Recommendation: Review the commit and restore authentication checks.
Finding 4: Author Email Mismatch
Severity: Medium
Risk Score: 50
Evidence: Author email changed from company email to personal Gmail.
Recommendation: Verify whether the commit was made by an authorized developer.
Troubleshooting
Problem: streamlit is not recognized

Use:

python -m streamlit run app.py

Or:

venv\Scripts\python.exe -m streamlit run app.py
Problem: No module named streamlit

Install Streamlit:

python -m pip install streamlit

Or install all packages:

python -m pip install streamlit gitpython pandas plotly reportlab
Problem: requirements.txt not found

Make sure you are inside the correct project folder.

Run:

dir

You should see:

app.py
requirements.txt
README.md
analyzer
scripts
Problem: app.py does not exist

Move into the inner project folder:

cd git-repository-forensics-tool

Then run:

python -m streamlit run app.py
Problem: GitHub repository is not cloning

Check that:

Git is installed
Internet is working
GitHub URL is correct
Repository is public

Check Git installation:

git --version
Limitations
Works mainly with Git repositories.
Public GitHub repositories can be scanned directly.
Private repositories must be cloned manually first.
Some secret detections may produce false positives.
The tool cannot always confirm malicious intent.
Manual forensic review is still required for final confirmation.
Future Enhancements
GitHub API integration
GitLab API integration
Pull request forensic analysis
Branch deletion detection
Machine learning-based suspicious commit detection
SIEM integration
Email alert system
Docker deployment
Advanced secret scanning
Commit graph visualization
Conclusion

The Git Repository Forensics and Insider Code Tampering Investigation Tool is a useful cybersecurity project for source code forensic investigation.

It helps identify secret leakage, suspicious commits, deleted sensitive files, author mismatch, and possible insider code tampering.

This project is suitable for major project submission because it includes digital forensics, Git analysis, automation, dashboard visualization, risk scoring, and forensic report generation.
