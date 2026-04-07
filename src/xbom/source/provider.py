"""Source provider abstraction for resolving scan targets to local paths."""

from __future__ import annotations

import re
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from xbom.config import get_token_for_provider
from xbom.models import SourceInfo
from xbom.utils.subprocess import run


class SourceProvider(ABC):
    """Base class for source providers."""

    @abstractmethod
    def resolve(self, target: str, *, branch: str | None = None, token: str | None = None) -> SourceInfo:
        """Resolve a target (path or URL) to a local path with metadata."""

    @abstractmethod
    def cleanup(self, info: SourceInfo) -> None:
        """Clean up any temporary resources."""


class LocalProvider(SourceProvider):
    """Handles local filesystem paths."""

    def resolve(self, target: str, *, branch: str | None = None, token: str | None = None) -> SourceInfo:
        path = Path(target).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")

        # Try to get git info if it's a git repo
        commit_sha = None
        actual_branch = None
        result = run(["git", "rev-parse", "HEAD"], cwd=path)
        if result.success:
            commit_sha = result.stdout.strip()
        result = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=path)
        if result.success:
            actual_branch = result.stdout.strip()

        return SourceInfo(
            local_path=path,
            provider="local",
            branch=actual_branch,
            commit_sha=commit_sha,
        )

    def cleanup(self, info: SourceInfo) -> None:
        pass  # Nothing to clean up for local paths


class GitProvider(SourceProvider):
    """Handles remote git repositories (GitHub, GitLab, Bitbucket)."""

    def __init__(self, provider_name: str):
        self.provider_name = provider_name

    def resolve(self, target: str, *, branch: str | None = None, token: str | None = None) -> SourceInfo:
        token = get_token_for_provider(self.provider_name, token)
        org, repo = self._parse_url(target)

        clone_url = self._build_clone_url(target, token)
        tmp_dir = tempfile.mkdtemp(prefix=f"xbom-{repo}-")
        tmp_path = Path(tmp_dir)

        # Shallow clone for speed
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([clone_url, str(tmp_path / repo)])

        result = run(cmd, timeout=120)
        if not result.success:
            raise RuntimeError(f"git clone failed: {result.stderr}")

        repo_path = tmp_path / repo

        # Get commit SHA
        commit_result = run(["git", "rev-parse", "HEAD"], cwd=repo_path)
        commit_sha = commit_result.stdout.strip() if commit_result.success else None

        # Get actual branch
        branch_result = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path)
        actual_branch = branch_result.stdout.strip() if branch_result.success else branch

        return SourceInfo(
            local_path=repo_path,
            provider=self.provider_name,
            org=org,
            repo=repo,
            branch=actual_branch,
            commit_sha=commit_sha,
            url=target,
            is_temp=True,
        )

    def cleanup(self, info: SourceInfo) -> None:
        if info.is_temp and info.local_path.exists():
            import shutil

            shutil.rmtree(info.local_path.parent, ignore_errors=True)

    def _parse_url(self, url: str) -> tuple[str, str]:
        """Extract org and repo from a git URL."""
        # HTTPS: https://github.com/org/repo or https://github.com/org/repo.git
        match = re.match(r"https?://[^/]+/([^/]+)/([^/]+?)(?:\.git)?/?$", url)
        if match:
            return match.group(1), match.group(2)
        # SSH: git@github.com:org/repo.git
        match = re.match(r"git@[^:]+:([^/]+)/([^/]+?)(?:\.git)?$", url)
        if match:
            return match.group(1), match.group(2)
        raise ValueError(f"Cannot parse git URL: {url}")

    def _build_clone_url(self, url: str, token: str | None) -> str:
        """Inject token into HTTPS clone URL if available."""
        if not token or not url.startswith("http"):
            return url
        # https://github.com/... → https://x-access-token:TOKEN@github.com/...
        return re.sub(r"(https?://)", rf"\1x-access-token:{token}@", url)


# Provider registry
_PROVIDERS: dict[str, type[SourceProvider]] = {}


def detect_provider(target: str) -> SourceProvider:
    """Auto-detect the appropriate source provider for a target."""
    # Local path
    if target.startswith("/") or target.startswith("./") or target.startswith("~") or not target.startswith(("http", "git@")):
        path = Path(target).expanduser()
        if path.exists():
            return LocalProvider()

    # GitHub
    if "github.com" in target:
        return GitProvider("github")

    # GitLab
    if "gitlab" in target:
        return GitProvider("gitlab")

    # Bitbucket
    if "bitbucket.org" in target:
        return GitProvider("bitbucket")

    # SSH URLs
    if target.startswith("git@"):
        if "github" in target:
            return GitProvider("github")
        if "gitlab" in target:
            return GitProvider("gitlab")
        if "bitbucket" in target:
            return GitProvider("bitbucket")
        return GitProvider("git")

    # Default: try as local path
    return LocalProvider()
