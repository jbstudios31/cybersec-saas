import sys

sys.path.insert(0, "scanner")

from checks import scan_target  # noqa: E402


def test_scan_target_returns_list():
    result = scan_target("https://example.com")
    assert isinstance(result, list)
    for f in result:
        assert "severity" in f
        assert "title" in f
        assert "description" in f
        assert "remediation" in f
        assert f["severity"] in ("low", "medium", "high", "critical")
