# Git Repository Forensics and Insider Code Tampering Investigation Tool

## GitHub URL Scanning

The dashboard now accepts a public GitHub repository URL directly. Example:

```text
https://github.com/owner/repository
```

When you click **Start Forensic Scan**, the tool automatically clones the repository into the `cloned_repositories/` folder and then performs forensic analysis on that local copy.

Private repositories require authentication and are not supported in this basic version. For private repositories, clone the repository manually and scan the local path.

This project analyzes a **GitHub repository or local Git repository** and detects forensic indicators such as:

- Secret leakage in commit history
- Sensitive files added, modified, or deleted
- Deleted file evidence
- Suspicious commit messages
- Large code deletions
- Security/authentication code modification
- Author email mismatch
- Risk scoring and severity classification
- Dashboard visualization
- PDF forensic report generation

## Technology Stack

- Python
- GitPython
- Streamlit
- Pandas
- Plotly
- SQLite
- ReportLab

## Project Structure

```text
git-repository-forensics-tool/
│
├── app.py
├── requirements.txt
├── README.md
│
├── analyzer/
│   ├── __init__.py
│   ├── git_collector.py
│   ├── secret_detector.py
│   ├── sensitive_file_detector.py
│   ├── suspicious_commit_detector.py
│   ├── author_analyzer.py
│   ├── risk_scoring.py
│   ├── db.py
│   ├── scanner.py
│   └── report_generator.py
│
├── scripts/
│   └── create_test_repo.py
│
├── database/
│   └── findings.db
│
├── reports/
│   └── generated PDF reports
│
└── test_repositories/
```

## Installation

```bash
python -m venv venv
```

### Windows

```bash
venv\Scripts\activate
```

### Linux / Kali

```bash
source venv/bin/activate
```

Install requirements:

```bash
pip install -r requirements.txt
```

## Create a Demo Repository

```bash
python scripts/create_test_repo.py
```

This creates a sample vulnerable Git repository inside:

```text
test_repositories/demo_employee_portal
```

## Run the Dashboard

```bash
streamlit run app.py
```

Then enter the demo repository path shown above and click **Start Forensic Scan**.

## Output

The tool generates:

- Dashboard metrics
- Timeline table
- Findings table
- Contributor activity chart
- Risk severity chart
- PDF investigation report
- SQLite findings database

## Notes

This tool is for defensive cybersecurity, digital forensics, DevSecOps, and academic project demonstration. It analyzes only repositories that you own or have permission to investigate.