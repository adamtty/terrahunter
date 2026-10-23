import pytest

from terrahunter import scanners


@pytest.fixture(autouse=True)
def no_real_scanners(monkeypatch, request):
    """Tests get scanners that find nothing (instantly, with no trivy or checkov needed); a test that wants
    findings sets its own runners, and the `real_scanners` mark keeps the installed ones."""
    if request.node.get_closest_marker("real_scanners"):
        return
    monkeypatch.setattr(scanners, "RUNNERS", {"trivy": lambda d, w: ([], []), "checkov": lambda d, w: ([], [])})
    monkeypatch.setattr(scanners, "scanner_version", lambda name, home: "9.9.9")
