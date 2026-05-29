"""Regression coverage for Copilot Enterprise IDE-auth headers."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ENTERPRISE_BASE = "https://api.enterprise.githubcopilot.com"


def test_agent_init_adds_copilot_headers_for_enterprise_base_url():
    """Enterprise Copilot host should get the same IDE auth headers as public Copilot."""
    from run_agent import AIAgent

    with patch("run_agent.OpenAI") as mock_openai:
        mock_openai.return_value = MagicMock()
        AIAgent(
            api_key="gh-token",
            base_url=ENTERPRISE_BASE,
            provider="copilot",
            model="gpt-5.5",
            quiet_mode=True,
            skip_memory=True,
            skip_context_files=True,
        )

    headers = mock_openai.call_args.kwargs.get("default_headers") or {}
    assert headers["Editor-Version"].startswith("vscode/")
    assert headers["Copilot-Integration-Id"] == "vscode-chat"
    assert headers["Openai-Intent"] == "conversation-edits"
    assert headers["x-initiator"] == "agent"


def test_resolve_provider_client_adds_copilot_headers_for_enterprise_base_url(monkeypatch):
    """Fallback/auxiliary clients resolved through Copilot Enterprise must preserve headers."""
    from agent.auxiliary_client import resolve_provider_client

    created = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            created.update(kwargs)
            self.api_key = kwargs.get("api_key")
            self.base_url = SimpleNamespace(__str__=lambda self: kwargs.get("base_url"))
            self._custom_headers = kwargs.get("default_headers")

    monkeypatch.setattr(
        "hermes_cli.auth.resolve_api_key_provider_credentials",
        lambda provider: {
            "api_key": "gh-token",
            "base_url": ENTERPRISE_BASE,
        },
    )
    monkeypatch.setattr("agent.auxiliary_client.OpenAI", FakeOpenAI)

    client, model = resolve_provider_client("copilot", model="gpt-5-mini")

    assert client is not None
    assert model == "gpt-5-mini"
    headers = created.get("default_headers") or {}
    assert headers["Editor-Version"].startswith("vscode/")
    assert headers["Copilot-Integration-Id"] == "vscode-chat"
    assert headers["Openai-Intent"] == "conversation-edits"
    assert headers["x-initiator"] == "agent"


def test_build_api_kwargs_marks_enterprise_base_as_github_responses():
    """Copilot Enterprise Responses calls need the GitHub/Copilot request shape."""
    from run_agent import AIAgent

    with patch("run_agent.OpenAI") as mock_openai:
        mock_openai.return_value = MagicMock()
        agent = AIAgent(
            api_key="gh-token",
            base_url=ENTERPRISE_BASE,
            provider="copilot",
            api_mode="codex_responses",
            model="gpt-5.5",
            quiet_mode=True,
            skip_memory=True,
            skip_context_files=True,
            reasoning_config={"enabled": True, "effort": "medium"},
        )

    kwargs = agent._build_api_kwargs([{"role": "user", "content": "hi"}])

    assert kwargs.get("reasoning") == {"effort": "medium"}
    assert "include" not in kwargs
