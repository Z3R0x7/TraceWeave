import json
from dataclasses import replace

import httpx
import pytest

from api.config import Settings
from api.reports import Provider, cache_key, generate, html_report, sanitize


@pytest.fixture
def payload():
    return {"incident": {"title": "<script>alert(1)</script>", "engine_review": {"version": "1"}},
            "facts": [{"fact_id": "step_01", "text": "Office launched PowerShell",
                       "evidence_ids": ["evt_01"], "entity_ids": ["host:a"],
                       "technique_ids": ["T1059.001"], "status": "observed"}],
            "reachability": {"message": "No access evidence", "candidates": []},
            "evidence": [{"evidence_id": "evt_01", "evidence_excerpt": "Office launched PowerShell"}],
            "dataset_quality": {"malformed_records": 1}}


def test_disabled_no_external_calls(payload, monkeypatch):
    monkeypatch.setattr(Provider, "request", lambda *a: pytest.fail("Unexpected API call"))
    assert generate(Settings(ai_provider="disabled"), payload)["source"] == "deterministic"


def test_verified_narrative(payload, monkeypatch):
    response = {"explanations": [{"fact_id": "step_01", "explanation": "Office ran PowerShell.",
                                 "evidence_ids": ["evt_01"], "entity_ids": ["host:a"],
                                 "technique_ids": ["T1059.001"], "interpretation_status": "observed"}]}
    outputs = iter([json.dumps(response), json.dumps({
        "supported_fact_ids": ["step_01"], "unsupported_claims": []
    })])
    monkeypatch.setattr(Provider, "request", lambda *a: next(outputs))
    assert generate(Settings(ai_provider="openai", ai_model="configured"), payload)["source"] == "openai"


@pytest.mark.parametrize("failure", ["invalid_json", "invented_id", "semantic_failure",
                                          "timeout", "rate_limit"])
def test_invalid_narrative_falls_back(payload, monkeypatch, failure):
    response = {"explanations": [{"fact_id": "step_01", "explanation": "Attacker has admin access",
                                 "evidence_ids": ["evt_01"], "entity_ids": ["host:a"],
                                 "technique_ids": ["T1059.001"], "interpretation_status": "observed"}]}
    if failure == "invented_id":
        response["explanations"][0]["evidence_ids"] = ["invented"]
    outputs = iter(["nonsense" if failure == "invalid_json" else json.dumps(response),
                    json.dumps({"supported_fact_ids": [], "unsupported_claims": ["admin access"]})])
    def request(*args):
        if failure == "timeout":
            raise httpx.ReadTimeout("timeout")
        if failure == "rate_limit":
            raise httpx.HTTPStatusError("429", request=httpx.Request("POST", "https://example.com"),
                                        response=httpx.Response(429))
        return next(outputs)
    monkeypatch.setattr(Provider, "request", request)
    result = generate(Settings(ai_provider="groq", ai_model="configured"), payload)
    assert result["source"] == "deterministic"
    assert result["warning"]


def test_cache_fingerprint_and_html(payload):
    settings = Settings(ai_provider="openai", ai_model="one")
    assert cache_key(settings, payload) != cache_key(replace(settings, ai_model="two"), payload)
    before = cache_key(settings, payload)
    payload["facts"][0]["text"] += " changed"
    assert before != cache_key(settings, payload)
    document = html_report(generate(Settings(ai_provider="disabled"), payload))
    assert "<script>" not in document
    assert "&lt;script&gt;" in document


def test_secret_sanitization():
    value = sanitize({"password": "secret", "text": "token=abcdef bearer abc123 sk-abcdefgh"})
    assert "secret" not in json.dumps(value)
    assert "abcdef" not in json.dumps(value)


@pytest.mark.parametrize("provider", ["openai", "groq"])
def test_provider_http_shape(monkeypatch, provider):
    monkeypatch.setenv(f"{provider.upper()}_API_KEY", "test-key")
    original = httpx.Client
    def handle(request):
        body = json.loads(request.content)
        assert body["model"] == "configured"
        assert request.headers["authorization"] == "Bearer test-key"
        if provider == "openai":
            assert body["store"] is False
            return httpx.Response(200, json={"output": [{"content": [
                {"type": "output_text", "text": "ready"}
            ]}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}}]})
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(
        transport=httpx.MockTransport(handle), **kwargs
    ))
    assert Provider(Settings(ai_provider=provider, ai_model="configured")).request("hello") == "ready"
