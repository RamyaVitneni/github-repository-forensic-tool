from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from .risk_scoring import build_finding


SUSPICIOUS_MESSAGE_KEYWORDS = [
    "bypass",
    "disable auth",
    "remove validation",
    "temporary fix",
    "temp fix",
    "hardcoded",
    "backdoor",
    "skip verification",
    "no auth",
    "debug only",
    "test credentials",
]

SECURITY_RELATED_FILES = [
    "auth.py",
    "auth.js",
    "authentication.py",
    "authentication.js",
    "authorization.py",
    "authorization.js",
    "login.py",
    "login.js",
    "security.py",
    "security.js",
    "middleware.py",
    "middleware.js",
    "jwt.py",
    "jwt.js",
    "permissions.py",
    "permissions.js",
    "roles.py",
    "roles.js",
]

SECURITY_RELATED_WORDS = [
    "auth",
    "login",
    "jwt",
    "permission",
    "role",
    "security",
    "middleware",
    "verify",
    "validate",
]


def _is_security_file(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    name = PurePosixPath(normalized).name
    if name in SECURITY_RELATED_FILES:
        return True
    return any(word in normalized for word in SECURITY_RELATED_WORDS)


def detect_suspicious_commits(
    commits: list[dict[str, Any]],
    large_deletion_threshold: int = 100,
    many_files_threshold: int = 10,
) -> list[dict[str, Any]]:
    """Detect suspicious commit-level behavior."""
    findings: list[dict[str, Any]] = []

    for commit in commits:
        message = commit.get("commit_message", "")
        message_lower = message.lower()

        for keyword in SUSPICIOUS_MESSAGE_KEYWORDS:
            if keyword in message_lower:
                findings.append(
                    build_finding(
                        finding_type="Suspicious Commit Message",
                        commit_hash=commit["commit_hash"],
                        author_name=commit["author_name"],
                        author_email=commit["author_email"],
                        commit_date=commit["commit_date"],
                        evidence=f"Commit message contains suspicious keyword: '{keyword}'",
                        commit_message=message,
                    )
                )
                break

        if commit.get("lines_deleted", 0) >= large_deletion_threshold:
            findings.append(
                build_finding(
                    finding_type="Large Code Deletion",
                    commit_hash=commit["commit_hash"],
                    author_name=commit["author_name"],
                    author_email=commit["author_email"],
                    commit_date=commit["commit_date"],
                    evidence=f"Commit deleted {commit.get('lines_deleted', 0)} lines.",
                    commit_message=message,
                )
            )

        if commit.get("files_changed_count", 0) >= many_files_threshold:
            findings.append(
                build_finding(
                    finding_type="Many Files Modified",
                    commit_hash=commit["commit_hash"],
                    author_name=commit["author_name"],
                    author_email=commit["author_email"],
                    commit_date=commit["commit_date"],
                    evidence=f"Commit changed {commit.get('files_changed_count', 0)} files.",
                    commit_message=message,
                )
            )

        hour = commit.get("commit_hour", 12)
        if hour < 6 or hour > 22:
            findings.append(
                build_finding(
                    finding_type="Outside Working Hours Commit",
                    commit_hash=commit["commit_hash"],
                    author_name=commit["author_name"],
                    author_email=commit["author_email"],
                    commit_date=commit["commit_date"],
                    evidence=f"Commit made outside normal working hours at hour {hour}.",
                    commit_message=message,
                )
            )

        for changed_file in commit.get("changed_files", []):
            file_path = changed_file.get("file_path", "")
            if _is_security_file(file_path):
                diff_text = changed_file.get("diff_text", "").lower()
                evidence = f"Security-related file modified: {file_path}"
                finding_type = "Authentication Code Modified"

                if any(term in diff_text for term in ["-validate", "-verify", "-authenticate", "-authorize", "-check_password"]):
                    evidence = f"Possible authentication or validation logic removed in {file_path}"

                findings.append(
                    build_finding(
                        finding_type=finding_type,
                        commit_hash=commit["commit_hash"],
                        author_name=commit["author_name"],
                        author_email=commit["author_email"],
                        commit_date=commit["commit_date"],
                        file_path=file_path,
                        evidence=evidence,
                        commit_message=message,
                    )
                )
                break

    return findings
