from __future__ import annotations

import re
from typing import Any

from .risk_scoring import build_finding


SECRET_PATTERNS = [
    ("Private Key Found", re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH |)?PRIVATE KEY-----", re.I)),
    ("Password Found", re.compile(r"(?i)(password|passwd|pwd|db_password)\s*[:=]\s*['\"]?[^\s'\"]{4,}")),
    ("API Token Found", re.compile(r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|jwt)\s*[:=]\s*['\"]?[^\s'\"]{8,}")),
    ("Secret Found", re.compile(r"(?i)(secret|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?[^\s'\"]{6,}")),
    ("API Token Found", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Secret Found", re.compile(r"(?i)mongodb(\+srv)?://[^\s]+")),
    ("Secret Found", re.compile(r"(?i)mysql://[^\s]+")),
    ("Secret Found", re.compile(r"(?i)postgres(ql)?://[^\s]+")),
]


def _added_lines_from_diff(diff_text: str) -> list[str]:
    """Return only added lines from a unified diff."""
    lines: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            lines.append(line[1:].strip())
    return lines


def _mask_secret(evidence: str) -> str:
    """Mask long secret values while preserving forensic usefulness."""
    if len(evidence) <= 80:
        return evidence
    return evidence[:77] + "..."


def detect_secrets(commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Scan added lines in commit diffs for hardcoded secrets."""
    findings: list[dict[str, Any]] = []

    for commit in commits:
        for changed_file in commit.get("changed_files", []):
            file_path = changed_file.get("file_path", "")
            diff_text = changed_file.get("diff_text", "")
            for line in _added_lines_from_diff(diff_text):
                if not line or line.startswith("#"):
                    continue
                for finding_type, pattern in SECRET_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            build_finding(
                                finding_type=finding_type,
                                commit_hash=commit["commit_hash"],
                                author_name=commit["author_name"],
                                author_email=commit["author_email"],
                                commit_date=commit["commit_date"],
                                file_path=file_path,
                                evidence=_mask_secret(line),
                                commit_message=commit["commit_message"],
                            )
                        )
                        break
    return findings
