from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from .author_analyzer import analyze_author_identity
from .db import save_findings
from .git_collector import collect_commits, get_repository_summary
from .repository_source import prepare_repository_source
from .secret_detector import detect_secrets
from .sensitive_file_detector import detect_sensitive_files
from .suspicious_commit_detector import detect_suspicious_commits


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove exact duplicate findings."""
    seen = set()
    unique = []
    for f in findings:
        key = (
            f.get("finding_type"),
            f.get("commit_hash"),
            f.get("file_path"),
            f.get("evidence"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_repository(repo_path: str, investigator_name: str = "Investigator") -> dict[str, Any]:
    """Run full Git repository forensic scan."""
    case_id = f"GIT-CASE-{uuid4().hex[:8].upper()}"
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    prepared_source = prepare_repository_source(repo_path)
    local_repo_path = str(prepared_source["repo_path"])

    summary = get_repository_summary(local_repo_path)
    summary["source_type"] = prepared_source["source_type"]
    summary["source_url"] = prepared_source["source_url"]
    summary["original_input"] = repo_path
    summary["was_cloned"] = prepared_source["was_cloned"]

    commits = collect_commits(local_repo_path)

    findings = []
    findings.extend(detect_secrets(commits))
    findings.extend(detect_sensitive_files(commits))
    findings.extend(detect_suspicious_commits(commits))
    findings.extend(analyze_author_identity(commits))

    findings = deduplicate_findings(findings)
    findings.sort(key=lambda f: f.get("risk_score", 0), reverse=True)

    high_risk_count = sum(1 for f in findings if f.get("severity") in {"Critical", "High"})
    secrets_count = sum(1 for f in findings if f.get("finding_type") in {"Private Key Found", "Password Found", "API Token Found", "Secret Found"})
    deleted_sensitive_count = sum(1 for f in findings if f.get("finding_type") == "Sensitive File Deleted")
    suspicious_commit_hashes = {f.get("commit_hash") for f in findings if f.get("commit_hash")}

    result = {
        "case_id": case_id,
        "investigator_name": investigator_name,
        "scan_date": scan_date,
        "summary": summary,
        "commits": commits,
        "findings": findings,
        "metrics": {
            "total_commits_analyzed": len(commits),
            "total_contributors": summary.get("total_contributors", 0),
            "total_findings": len(findings),
            "suspicious_commits": len(suspicious_commit_hashes),
            "secrets_detected": secrets_count,
            "deleted_sensitive_files": deleted_sensitive_count,
            "high_risk_findings": high_risk_count,
        },
    }

    save_findings(case_id, summary["repo_name"], scan_date, findings)
    return result
