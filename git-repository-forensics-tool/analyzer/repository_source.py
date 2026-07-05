from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

from git import GitCommandError, Repo

from .git_collector import GitRepositoryError


def is_github_url(source: str) -> bool:
    """Return True when the input looks like a GitHub repository URL."""
    value = (source or "").strip()
    if not value:
        return False

    if value.startswith("git@github.com:"):
        return True

    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and parsed.netloc.lower() in {
        "github.com",
        "www.github.com",
    }


def _clean_repo_url(repo_url: str) -> str:
    """Normalize common GitHub web URLs into clone-friendly repository URLs."""
    value = repo_url.strip()

    # Remove URL fragments and query strings from copied browser URLs.
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        parts = [p for p in parsed.path.split("/") if p]

        if len(parts) < 2:
            raise GitRepositoryError(
                "Invalid GitHub URL. Use this format: https://github.com/owner/repository"
            )

        owner, repo = parts[0], parts[1]
        repo = repo[:-4] if repo.endswith(".git") else repo
        return f"https://github.com/{owner}/{repo}.git"

    # SSH format: git@github.com:owner/repository.git
    if value.startswith("git@github.com:"):
        return value

    return value


def _repo_folder_name(repo_url: str) -> str:
    """Create a safe local folder name for the cloned repository."""
    cleaned = _clean_repo_url(repo_url)
    unique_hash = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:8]

    if cleaned.startswith("git@github.com:"):
        path_part = cleaned.split(":", 1)[1]
        parts = [p for p in path_part.split("/") if p]
    else:
        parsed = urlparse(cleaned)
        parts = [p for p in parsed.path.split("/") if p]

    owner = parts[-2] if len(parts) >= 2 else "github"
    repo = parts[-1] if parts else "repository"
    repo = repo[:-4] if repo.endswith(".git") else repo

    name = f"{owner}_{repo}_{unique_hash}"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def clone_github_repository(repo_url: str, base_dir: str | Path = "cloned_repositories") -> Path:
    """
    Clone a GitHub repository URL into a local folder and return the cloned path.

    The scan modules still analyze a local Git folder internally because Git history
    must be available on disk. This function automatically creates that local copy.
    """
    clone_url = _clean_repo_url(repo_url)
    base_path = Path(base_dir).resolve()
    base_path.mkdir(parents=True, exist_ok=True)

    target_path = base_path / _repo_folder_name(clone_url)

    # Fresh clone every scan so the dashboard analyzes the latest public repository state.
    if target_path.exists():
        try:
            shutil.rmtree(target_path)
        except PermissionError as exc:
            raise GitRepositoryError(
                f"Cannot replace old cloned copy: {target_path}. Close files from this folder and try again."
            ) from exc

    try:
        Repo.clone_from(clone_url, str(target_path))
    except GitCommandError as exc:
        raise GitRepositoryError(
            "Could not clone the GitHub repository. Check that the URL is correct, the repository is public, "
            "your internet connection is working, and Git is installed on your system."
        ) from exc

    return target_path


def prepare_repository_source(source: str) -> dict[str, str | bool]:
    """
    Convert a GitHub URL into a cloned local path.
    Local paths are returned unchanged.
    """
    value = (source or "").strip()
    if not value:
        raise GitRepositoryError("Please enter a GitHub repository URL or local Git repository path.")

    if is_github_url(value):
        cloned_path = clone_github_repository(value)
        return {
            "repo_path": str(cloned_path),
            "source_type": "GitHub URL",
            "source_url": value,
            "was_cloned": True,
        }

    return {
        "repo_path": value,
        "source_type": "Local Path",
        "source_url": "",
        "was_cloned": False,
    }
