from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from .risk_scoring import build_finding


SENSITIVE_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "credentials.txt",
    "credentials.json",
    "secrets.json",
    "secret.json",
    "config.json",
    "database.yml",
    "database.yaml",
    "private.key",
    "id_rsa",
    "id_dsa",
    "settings.py",
    "application.properties",
    "application.yml",
    "firebase-config.json",
}

SENSITIVE_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".crt",
}


def is_sensitive_file(file_path: str) -> bool:
    """Return True if path looks like a sensitive file."""
    normalized = file_path.replace("\\", "/")
    name = PurePosixPath(normalized).name.lower()
    suffix = PurePosixPath(normalized).suffix.lower()
    return name in SENSITIVE_FILE_NAMES or suffix in SENSITIVE_EXTENSIONS


def detect_sensitive_files(commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect sensitive files added, modified, or deleted from history."""
    findings: list[dict[str, Any]] = []

    for commit in commits:
        for changed_file in commit.get("changed_files", []):
            file_path = changed_file.get("file_path", "")
            if not is_sensitive_file(file_path):
                continue

            status = changed_file.get("status", "")
            if status == "A":
                finding_type = "Sensitive File Added"
                evidence = f"Sensitive file added: {file_path}"
            elif status == "D":
                finding_type = "Sensitive File Deleted"
                evidence = f"Sensitive file deleted from repository history: {file_path}"
            else:
                finding_type = "Sensitive File Modified"
                evidence = f"Sensitive file modified: {file_path}"

            findings.append(
                build_finding(
                    finding_type=finding_type,
                    commit_hash=commit["commit_hash"],
                    author_name=commit["author_name"],
                    author_email=commit["author_email"],
                    commit_date=commit["commit_date"],
                    file_path=file_path,
                    evidence=evidence,
                    commit_message=commit["commit_message"],
                )
            )
    return findings
