"""Copilot / GitHub Models URL helpers."""

from __future__ import annotations

from utils import base_url_hostname, base_url_host_matches


COPILOT_HOST_SUFFIX = "githubcopilot.com"


def is_copilot_base_url(base_url: str | None) -> bool:
    """Return True for public and Enterprise GitHub Copilot API hosts.

    Enterprise Copilot can use hosts such as
    ``api.enterprise.githubcopilot.com``. Those hosts require the same IDE auth
    headers as ``api.githubcopilot.com``; exact-host checks silently drop them.
    """
    return base_url_host_matches(str(base_url or ""), COPILOT_HOST_SUFFIX)


def is_github_models_base_url(base_url: str | None) -> bool:
    """Return True for GitHub Models / Copilot-compatible inference hosts."""
    host = base_url_hostname(str(base_url or ""))
    return (
        host == "models.github.ai"
        or host == "models.inference.ai.azure.com"
        or is_copilot_base_url(base_url)
    )
