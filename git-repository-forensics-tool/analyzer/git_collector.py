from __future__ import annotations

from pathlib import Path
from typing import Any

from git import Repo, InvalidGitRepositoryError, NoSuchPathError


class GitRepositoryError(Exception):
    """Raised when the repository path is invalid."""


def validate_repo_path(repo_path: str) -> Path:
    """Validate that repo_path points to a local Git repository."""
    path = Path(repo_path).expanduser().resolve()
    if not path.exists():
        raise GitRepositoryError(f"Path does not exist: {path}")
    if not (path / ".git").exists():
        raise GitRepositoryError(f"The selected folder is not a Git repository: {path}")
    try:
        Repo(str(path))
    except (InvalidGitRepositoryError, NoSuchPathError) as exc:
        raise GitRepositoryError(f"Invalid Git repository: {path}") from exc
    return path


def get_repository_summary(repo_path: str) -> dict[str, Any]:
    """Return basic repository information."""
    path = validate_repo_path(repo_path)
    repo = Repo(str(path))
    branches = [head.name for head in repo.heads]
    active_branch = "DETACHED"
    try:
        active_branch = repo.active_branch.name
    except TypeError:
        pass

    commits = list(repo.iter_commits("--all"))
    contributors = sorted({c.author.email for c in commits if c.author.email})

    return {
        "repo_name": path.name,
        "repo_path": str(path),
        "active_branch": active_branch,
        "branches": branches,
        "total_commits": len(commits),
        "total_contributors": len(contributors),
    }


def _safe_diff_text(diff_obj) -> str:
    """Return diff text safely without crashing on binary files."""
    try:
        return diff_obj.diff.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _count_added_deleted(diff_text: str) -> tuple[int, int]:
    """Count inserted and deleted lines from unified diff text."""
    added = 0
    deleted = 0
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            deleted += 1
    return added, deleted


def collect_commits(repo_path: str) -> list[dict[str, Any]]:
    """
    Extract commit metadata and file-level diff evidence from a repository.

    Returns one dictionary per commit with nested changed file details.
    """
    path = validate_repo_path(repo_path)
    repo = Repo(str(path))
    commits_data: list[dict[str, Any]] = []

    for commit in repo.iter_commits("--all"):
        parent = commit.parents[0] if commit.parents else None

        if parent:
            diffs = parent.diff(commit, create_patch=True)
        else:
            # Root commit: compare against empty tree.
            diffs = commit.diff(NULL_TREE, create_patch=True)

        changed_files = []
        total_added = 0
        total_deleted = 0

        for d in diffs:
            old_path = d.a_path or ""
            new_path = d.b_path or old_path
            file_path = new_path or old_path
            diff_text = _safe_diff_text(d)
            added, deleted = _count_added_deleted(diff_text)
            total_added += added
            total_deleted += deleted

            status = "M"
            if d.new_file:
                status = "A"
            elif d.deleted_file:
                status = "D"
            elif d.renamed_file:
                status = "R"

            changed_files.append(
                {
                    "file_path": file_path,
                    "old_path": old_path,
                    "new_path": new_path,
                    "status": status,
                    "added_lines": added,
                    "deleted_lines": deleted,
                    "diff_text": diff_text,
                }
            )

        commits_data.append(
            {
                "commit_hash": commit.hexsha,
                "short_hash": commit.hexsha[:12],
                "author_name": commit.author.name,
                "author_email": commit.author.email,
                "commit_date": commit.committed_datetime.strftime("%Y-%m-%d %H:%M:%S %z"),
                "commit_hour": commit.committed_datetime.hour,
                "commit_message": commit.message.strip(),
                "files_changed_count": len(changed_files),
                "lines_added": total_added,
                "lines_deleted": total_deleted,
                "changed_files": changed_files,
            }
        )

    # Oldest first for investigation timeline.
    commits_data.sort(key=lambda x: x["commit_date"])
    return commits_data


# Git empty tree constant used for root commit diff.
NULL_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
