"""
Tests for the vendor model-id resolver.

Fixtures are drawn directly from the identifier table in
docs/vendor-disclosure-scanner-design.md — one row per surface. No network
access or vendor API key is required or used anywhere in this file.
"""

from aibom.scanner.vendor_resolver import resolve_model_id


class TestAnthropicDirect:
    def test_pinned_snapshot(self):
        r = resolve_model_id("claude-3-5-sonnet-20241022")
        assert r.resolved
        assert r.model_provider == "Anthropic"
        assert r.hosting_provider == "Anthropic"
        assert r.snapshot == "20241022"
        assert r.floating_alias is False

    def test_floating_latest_alias(self):
        r = resolve_model_id("claude-3-5-sonnet-latest")
        assert r.resolved
        assert r.model_provider == "Anthropic"
        assert r.floating_alias is True
        assert r.snapshot is None

    def test_generation_alias_no_date_is_floating(self):
        r = resolve_model_id("claude-sonnet-4-6")
        assert r.resolved
        assert r.model_provider == "Anthropic"
        assert r.floating_alias is True


class TestOpenAIDirect:
    def test_floating_no_date(self):
        r = resolve_model_id("gpt-4o")
        assert r.resolved
        assert r.model_provider == "OpenAI"
        assert r.floating_alias is True

    def test_pinned_snapshot(self):
        r = resolve_model_id("gpt-4o-2024-08-06")
        assert r.resolved
        assert r.model_provider == "OpenAI"
        assert r.snapshot == "20240806"
        assert r.floating_alias is False

    def test_o_series_prefix(self):
        r = resolve_model_id("o3-mini")
        assert r.resolved
        assert r.model_provider == "OpenAI"
        assert r.floating_alias is True


class TestGoogleAI:
    def test_floating_no_snapshot(self):
        r = resolve_model_id("gemini-1.5-pro")
        assert r.resolved
        assert r.model_provider == "Google"
        assert r.floating_alias is True

    def test_pinned_numeric_snapshot(self):
        r = resolve_model_id("gemini-1.5-pro-002")
        assert r.resolved
        assert r.model_provider == "Google"
        assert r.snapshot == "002"
        assert r.floating_alias is False

    def test_models_prefix_stripped(self):
        r = resolve_model_id("models/gemini-1.5-pro")
        assert r.resolved
        assert r.model_provider == "Google"
        assert r.floating_alias is True


class TestBedrock:
    def test_region_prefixed_inference_profile(self):
        r = resolve_model_id("us.anthropic.claude-3-5-sonnet-20241022-v2:0")
        assert r.resolved
        assert r.model_provider == "Anthropic"
        assert r.hosting_provider == "AWS (Bedrock)"
        assert r.snapshot == "20241022"
        assert r.floating_alias is False
        assert "AWS" in r.note


class TestAzureOpenAI:
    def test_deployment_name_unresolvable(self):
        r = resolve_model_id("my-gpt4-prod")
        assert r.resolved is False
        assert "Azure" in r.note or "custom deployment" in r.note


class TestVertex:
    def test_pinned_publisher_path(self):
        r = resolve_model_id("publishers/anthropic/models/claude-3-5-sonnet-v2@20241022")
        assert r.resolved
        assert r.model_provider == "Anthropic"
        assert r.hosting_provider == "Google (Vertex AI)"
        assert r.snapshot == "20241022"
        assert r.floating_alias is False


class TestOpenRouter:
    def test_floating_provider_slash_model(self):
        r = resolve_model_id("anthropic/claude-3.5-sonnet")
        assert r.resolved
        assert r.model_provider == "Anthropic"
        assert r.hosting_provider == "OpenRouter"
        assert r.floating_alias is True


class TestOpenWeight:
    def test_hf_org_name_form(self):
        r = resolve_model_id("meta-llama/Llama-3.1-70B-Instruct")
        assert r.resolved
        assert r.model_provider == "meta-llama"
        assert r.hosting_provider == "self-hosted / Hugging Face (open-weight)"
        assert r.floating_alias is False
        assert "license" in r.note.lower()


class TestDegradation:
    def test_empty_string(self):
        r = resolve_model_id("")
        assert r.resolved is False

    def test_unknown_shape_does_not_raise(self):
        r = resolve_model_id("!!!not-a-real-id###")
        assert r.resolved is False
        assert r.note
