"""Tests for mcp.shared.tee_helpers."""

from mcp.shared.tee_envelope import (
    extract_tee,
    extract_tee_from_result,
    inject_tee,
)


class TestExtractTeeDict:
    """Tests for extract_tee."""

    def test_none_params(self) -> None:
        assert extract_tee(None) is None

    def test_no_meta(self) -> None:
        class FakeParams:
            pass

        assert extract_tee(FakeParams()) is None

    def test_meta_no_tee(self) -> None:
        class FakeMeta:
            model_extra: dict = {}

        class FakeParams:
            meta = FakeMeta()

        assert extract_tee(FakeParams()) is None

    def test_meta_with_tee(self) -> None:
        tee = {"quote": "abc", "sig_data": "def"}

        class FakeMeta:
            model_extra: dict = {"tee": tee}

        class FakeParams:
            meta = FakeMeta()

        assert extract_tee(FakeParams()) is tee

    def test_meta_tee_as_attribute(self) -> None:
        """Test fallback to direct attribute access."""
        tee = {"quote": "abc"}

        class FakeMeta:
            model_extra: dict = {}

            def __init__(self) -> None:
                self.tee = tee  # type: ignore

        class FakeParams:
            meta = FakeMeta()

        assert extract_tee(FakeParams()) is tee

    def test_underscore_meta(self) -> None:
        """Test fallback to _meta attribute."""
        tee = {"quote": "abc"}

        class FakeMeta:
            model_extra: dict = {"tee": tee}

        class FakeParams:
            _meta = FakeMeta()

        assert extract_tee(FakeParams()) is tee


class TestInjectTee:
    """Tests for inject_tee."""

    def test_inject_empty_dict(self) -> None:
        d: dict = {}
        inject_tee(d, {"quote": "abc"})
        assert d == {"_meta": {"tee": {"quote": "abc"}}}

    def test_inject_existing_meta(self) -> None:
        d: dict = {"_meta": {"other": "val"}}
        inject_tee(d, {"quote": "abc"})
        assert d["_meta"]["tee"] == {"quote": "abc"}
        assert d["_meta"]["other"] == "val"

    def test_inject_params_level(self) -> None:
        d: dict = {}
        inject_tee(d, {"quote": "abc"}, params_level=True)
        assert d == {"params": {"_meta": {"tee": {"quote": "abc"}}}}

    def test_inject_params_level_existing(self) -> None:
        d: dict = {"params": {"name": "test"}}
        inject_tee(d, {"quote": "abc"}, params_level=True)
        assert d["params"]["_meta"]["tee"] == {"quote": "abc"}
        assert d["params"]["name"] == "test"


class TestExtractTeeFromResult:
    """Tests for extract_tee_from_result."""

    def test_empty_dict(self) -> None:
        assert extract_tee_from_result({}) is None

    def test_no_meta(self) -> None:
        assert extract_tee_from_result({"content": []}) is None

    def test_meta_no_tee(self) -> None:
        assert extract_tee_from_result({"_meta": {"other": "val"}}) is None

    def test_meta_with_tee(self) -> None:
        tee = {"quote": "abc"}
        assert extract_tee_from_result({"_meta": {"tee": tee}}) is tee

    def test_none_meta(self) -> None:
        assert extract_tee_from_result({"_meta": None}) is None


