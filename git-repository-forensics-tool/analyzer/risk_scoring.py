from __future__ import annotations

from dataclasses import dataclass


RISK_RULES = {
    "Private Key Found": 95,
    "Password Found": 90,
    "API Token Found": 85,
    "Secret Found": 85,
    "Sensitive File Deleted": 80,
    "Sensitive File Added": 75,
    "Authentication Code Modified": 75,
    "Large Code Deletion": 70,
    "Many Files Modified": 60,
    "Outside Working Hours Commit": 55,
    "Author Email Mismatch": 50,
    "Personal Email Used": 45,
    "Suspicious Commit Message": 40,
    "Sensitive File Modified": 65,
}


def get_risk_score(finding_type: str) -> int:
    """Return numeric risk score for a finding type."""
    return RISK_RULES.get(finding_type, 30)


def get_severity(score: int) -> str:
    """Convert risk score into severity."""
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def recommendation_for(finding_type: str) -> str:
    """Return practical remediation recommendation."""
    recommendations = {
        "Private Key Found": "Rotate the exposed key immediately, revoke old credentials, and remove it from Git history using a secure history-cleaning tool.",
        "Password Found": "Change the exposed password immediately and store credentials in a secret manager or environment variables.",
        "API Token Found": "Revoke the leaked API token, generate a new token, and audit token usage logs.",
        "Secret Found": "Validate whether the value is a real secret, rotate it if valid, and remove it from repository history.",
        "Sensitive File Deleted": "Review why the file was deleted and check older commits because deleted files may still exist in Git history.",
        "Sensitive File Added": "Move sensitive configuration outside the repository and add the file pattern to .gitignore.",
        "Sensitive File Modified": "Review the change, confirm no credentials are exposed, and move sensitive values to secure storage.",
        "Authentication Code Modified": "Manually review the commit and restore required authentication or authorization checks if removed.",
        "Large Code Deletion": "Review the deleted code carefully and verify that critical business or security logic was not removed.",
        "Many Files Modified": "Review the commit scope and confirm the change was approved and linked to a valid task.",
        "Outside Working Hours Commit": "Verify whether the commit time is expected for the developer or indicates unusual activity.",
        "Author Email Mismatch": "Verify the developer identity and check whether Git user configuration or account compromise caused the mismatch.",
        "Personal Email Used": "Confirm whether personal email usage is allowed and enforce organization-approved Git identities.",
        "Suspicious Commit Message": "Review the commit content because the message contains suspicious security-related terms.",
    }
    return recommendations.get(finding_type, "Review this finding manually and validate the risk with the repository owner.")


def build_finding(
    finding_type: str,
    commit_hash: str = "",
    author_name: str = "",
    author_email: str = "",
    commit_date: str = "",
    file_path: str = "",
    evidence: str = "",
    commit_message: str = "",
) -> dict:
    """Create a normalized finding dictionary."""
    score = get_risk_score(finding_type)
    return {
        "finding_type": finding_type,
        "commit_hash": commit_hash[:12] if commit_hash else "",
        "author_name": author_name,
        "author_email": author_email,
        "commit_date": commit_date,
        "file_path": file_path,
        "evidence": evidence,
        "commit_message": commit_message,
        "risk_score": score,
        "severity": get_severity(score),
        "recommendation": recommendation_for(finding_type),
    }
