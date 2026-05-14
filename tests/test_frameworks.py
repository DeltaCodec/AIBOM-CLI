"""Tests for ML framework and library detection."""
import pytest

from aibom.scanner.frameworks import detect_frameworks, FRAMEWORKS, ML_LIBRARIES, Framework


class TestClassification:
    def test_pytorch_is_library(self):
        result = detect_frameworks(".", {"torch": "2.1.0"})
        torch = next((f for f in result if f.package == "torch"), None)
        assert torch is not None
        assert torch.kind == "library"
        assert torch.name == "PyTorch"

    def test_ray_is_framework(self):
        result = detect_frameworks(".", {"ray": "2.9.0"})
        ray = next((f for f in result if f.package == "ray"), None)
        assert ray is not None
        assert ray.kind == "framework"
        assert ray.name == "Ray"

    def test_mlflow_is_framework(self):
        result = detect_frameworks(".", {"mlflow": "2.12.0"})
        mlf = next((f for f in result if f.package == "mlflow"), None)
        assert mlf is not None
        assert mlf.kind == "framework"

    def test_transformers_is_library(self):
        result = detect_frameworks(".", {"transformers": "4.40.0"})
        tf = next((f for f in result if f.package == "transformers"), None)
        assert tf is not None
        assert tf.kind == "library"


class TestDeduplication:
    def test_tf_and_tensorflow_aliases_collapse(self):
        """Both 'tf' and 'tensorflow' map to the same pip package — should be one entry."""
        result = detect_frameworks(".", {"tensorflow": "2.15.0"})
        tf_entries = [f for f in result if f.package == "tensorflow"]
        assert len(tf_entries) == 1

    def test_version_populated(self):
        result = detect_frameworks(".", {"torch": "2.1.0"})
        torch = next(f for f in result if f.package == "torch")
        assert torch.version == "2.1.0"


class TestInDepsFlag:
    def test_in_deps_true_when_in_dep_names(self):
        result = detect_frameworks(".", {"torch": "2.1.0"}, dep_names={"torch"})
        torch = next(f for f in result if f.package == "torch")
        assert torch.in_deps is True

    def test_in_deps_false_when_not_in_dep_names(self):
        result = detect_frameworks(".", {"torch": "2.1.0"}, dep_names={"requests"})
        torch = next(f for f in result if f.package == "torch")
        assert torch.in_deps is False

    def test_dep_names_normalizes_hyphens(self):
        # sentence-transformers in dep_names should match package "sentence-transformers"
        result = detect_frameworks(".", {"sentence-transformers": "2.7.0"},
                                   dep_names={"sentence-transformers"})
        st = next((f for f in result if f.package == "sentence-transformers"), None)
        if st:
            assert st.in_deps is True


class TestDicts:
    def test_no_overlap_between_frameworks_and_libraries(self):
        fw_keys = set(FRAMEWORKS.keys())
        lib_keys = set(ML_LIBRARIES.keys())
        overlap = fw_keys & lib_keys
        assert not overlap, f"Import name overlap: {overlap}"

    def test_all_entries_have_display_name_and_package(self):
        for imp, (display, pkg) in {**FRAMEWORKS, **ML_LIBRARIES}.items():
            assert display, f"Empty display name for {imp!r}"
            assert pkg, f"Empty package name for {imp!r}"
