from __future__ import annotations

from collections import defaultdict
from typing import Any

from .risk_scoring import build_finding


PERSONAL_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
}


def _domain(email: str) -> str:
    return email.split("@")[-1].lower().strip() if "@" in email else ""


def analyze_author_identity(commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect author identity mismatch and personal email usage."""
    findings: list[dict[str, Any]] = []
    author_emails: dict[str, set[str]] = defaultdict(set)

    for commit in commits:
        name = commit.get("author_name", "").strip().lower()
        email = commit.get("author_email", "").strip().lower()
        if name and email:
            author_emails[name].add(email)

    for author_name_lower, emails in author_emails.items():
        if len(emails) > 1:
            related_commits = [
                c for c in commits
                if c.get("author_name", "").strip().lower() == author_name_lower
            ]
            latest = related_commits[-1]
            findings.append(
                build_finding(
                    finding_type="Author Email Mismatch",
                    commit_hash=latest["commit_hash"],
                    author_name=latest["author_name"],
                    author_email=latest["author_email"],
                    commit_date=latest["commit_date"],
                    evidence=f"Same author name used multiple emails: {', '.join(sorted(emails))}",
                    commit_message=latest["commit_message"],
                )
            )

    for commit in commits:
        email = commit.get("author_email", "").strip().lower()
        domain = _domain(email)
        if domain in PERSONAL_EMAIL_DOMAINS:
            findings.append(
                build_finding(
                    finding_type="Personal Email Used",
                    commit_hash=commit["commit_hash"],
                    author_name=commit["author_name"],
                    author_email=commit["author_email"],
                    commit_date=commit["commit_date"],
                    evidence=f"Commit used personal email domain: {domain}",
                    commit_message=commit["commit_message"],
                )
            )

    return findings
