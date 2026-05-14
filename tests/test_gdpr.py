"""Tests for GDPR/LGPD privacy flagging."""
import pytest

from aibom.scanner.datasets import Dataset, _SAFE_DATASETS, _name_tokens, _norm_name
from aibom.compliance.gdpr import flag_gdpr


def _make_dataset(name: str, gdpr_risk: str = "HIGH", source_type: str = "web_scrape") -> Dataset:
    return Dataset(
        name=name,
        source="https://example.com",
        gdpr_risk=gdpr_risk,
        source_type=source_type,
        confidence="INFERRED",
    )


class TestSafeList:
    def test_wikipedia_is_suppressed(self):
        ds = _make_dataset("Wikipedia", gdpr_risk="LOW", source_type="licensed")
        flags = flag_gdpr([ds])
        names = [f.dataset_name for f in flags]
        assert "Wikipedia" not in names

    def test_imagenet_is_suppressed(self):
        ds = _make_dataset("ImageNet", gdpr_risk="LOW", source_type="licensed")
        flags = flag_gdpr([ds])
        assert not flags

    def test_arxiv_is_suppressed(self):
        ds = _make_dataset("ArXiv", gdpr_risk="LOW", source_type="licensed")
        flags = flag_gdpr([ds])
        assert not flags


class TestRiskLevels:
    def test_commoncrawl_is_high(self):
        ds = _make_dataset("CommonCrawl", gdpr_risk="HIGH", source_type="web_scrape")
        flags = flag_gdpr([ds])
        assert flags
        assert flags[0].risk_level == "HIGH"

    def test_low_risk_dataset_not_flagged(self):
        ds = _make_dataset("SyntheticData", gdpr_risk="LOW", source_type="synthetic")
        flags = flag_gdpr([ds])
        assert not flags


class TestTokenBoundaries:
    def test_name_tokens_split_on_hyphen(self):
        assert "user" in _name_tokens("user-data")

    def test_name_tokens_split_on_underscore(self):
        assert "user" in _name_tokens("user_profiles")

    def test_name_tokens_no_substring_match(self):
        # "username" should NOT match the token "user"
        tokens = _name_tokens("username-dataset")
        assert "username" in tokens
        assert "user" not in tokens

    def test_norm_name_lowercases(self):
        assert _norm_name("Wikipedia") == "wikipedia"

    def test_safe_datasets_are_lowercase(self):
        # All entries in _SAFE_DATASETS must be lowercase for case-insensitive matching
        for name in _SAFE_DATASETS:
            assert name == name.lower(), f"_SAFE_DATASETS entry not lowercase: {name!r}"
